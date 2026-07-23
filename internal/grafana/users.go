// SPDX-FileCopyrightText: 2025 Sebastian Küthe and (other) contributors to project grafana-oss-team-sync <https://github.com/skuethe/grafana-oss-team-sync>
// SPDX-License-Identifier: GPL-3.0-or-later

package grafana

import (
	"crypto/rand"
	"log/slog"
	"math/big"
	"slices"
	"strings"
	"sync"

	"github.com/grafana/grafana-openapi-client-go/models"
	"github.com/skuethe/grafana-oss-team-sync/internal/config"
	"github.com/skuethe/grafana-oss-team-sync/internal/config/configtypes"
)

type User models.AdminCreateUserForm

type Users []User

var (
	existingUsersOnce sync.Once
	existingUsers     map[string]struct{}
	existingUsersErr  error
)

func generateSecurePassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+"
	const length = 32

	password := make([]byte, length)
	charsetLength := big.NewInt(int64(len(charset)))
	for i := range password {
		index, _ := rand.Int(rand.Reader, charsetLength)
		password[i] = charset[index.Int64()]
	}

	return string(password)
}

// loadExistingUsers fetches every user of the current Grafana organisation
// once and caches them, keyed by lower-cased email and login.
//
// We deliberately use the org-scoped endpoint (GET /api/org/users) instead of
// the global lookup (GET /api/users/lookup): the latter requires server-admin
// (global users:read) permissions, which an org-Admin service-account token
// does not have, so with token auth it always returns 403 and every existence
// check fails.
func loadExistingUsers() (map[string]struct{}, error) {
	existingUsersOnce.Do(func() {
		set := make(map[string]struct{})
		resp, err := Instance.api.Org.GetOrgUsersForCurrentOrg(nil)
		if err != nil {
			existingUsersErr = err
			return
		}
		for _, orgUser := range resp.Payload {
			if orgUser.Email != "" {
				set[strings.ToLower(orgUser.Email)] = struct{}{}
			}
			if orgUser.Login != "" {
				set[strings.ToLower(orgUser.Login)] = struct{}{}
			}
		}
		existingUsers = set
	})
	return existingUsers, existingUsersErr
}

func (u *User) doesUserExist() bool {
	set, err := loadExistingUsers()
	if err != nil {
		slog.Error("could not load existing org users for existence check",
			slog.Any("error", err),
		)
		return false
	}
	// Match by email first: with Entra ID B2B guest accounts the
	// userPrincipalName (Login) is the mangled guest form
	// (user_domain.tld#EXT#@tenant.onmicrosoft.com) which never matches the
	// existing Grafana user, whereas the mail attribute does. Fall back to
	// login when no email is available.
	if u.Email != "" {
		if _, ok := set[strings.ToLower(u.Email)]; ok {
			return true
		}
	}
	if u.Login != "" {
		if _, ok := set[strings.ToLower(u.Login)]; ok {
			return true
		}
	}
	return false
}

func (u *User) createUser() error {
	_, err := Instance.api.AdminUsers.AdminCreateUser(&models.AdminCreateUserForm{
		Email:    u.Email,
		Login:    u.Login,
		Name:     u.Name,
		Password: models.Password(generateSecurePassword()),
	})
	if err != nil {
		return err
	}
	return nil
}

func (t *Teams) ProcessUsers() {
	usersLog := slog.With(slog.String("package", "grafana.users"))

	if config.Instance.Features.DisableUserSync {
		usersLog.Info("usersync feature disabled, skipping")
	} else if config.Instance.Features.AddExistingUsersOnly {
		usersLog.Info("addExistingUsersOnly feature enabled, skipping user creation")
	} else if len(*t) == 0 {
		usersLog.Info("no teams and therefore users to process, skipping")
	} else if config.Instance.Grafana.AuthType == configtypes.GrafanaAuthTypeToken {
		usersLog.Warn("can not process users with token auth, skipping")
	} else {
		usersLog.Info("processing users")

		countCreated := 0
		countDuplicate := 0
		countSkipped := 0

		globalUserList := &Users{}

		for _, team := range *t {
			for _, user := range *team.Users {
				userExists := false
				if slices.Contains(*globalUserList, user) {
					userExists = true
					usersLog.Debug("skipping duplicate user")
					countDuplicate++
				}
				if !userExists {
					*globalUserList = append(*globalUserList, user)
				}
			}
		}

		for _, user := range *globalUserList {

			userLog := slog.With(
				slog.Group("user",
					slog.String("login", user.Login),
					slog.String("email", user.Email),
				),
			)
			if user.doesUserExist() {
				countSkipped++
				userLog.Debug("skipping already existing user")
			} else {
				err := user.createUser()
				if err != nil {
					userLog.Error("could not create user",
						slog.Any("error", err),
					)
				} else {
					userLog.Info("created user")
					countCreated++
				}
			}
		}

		usersLog.Info("finished processing users",
			slog.Group("users",
				slog.Int("created", countCreated),
				slog.Int("existing", countSkipped),
			),
		)
	}

}

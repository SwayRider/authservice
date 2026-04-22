// i18n.go provides internationalization support for web templates.
//
// Currently supported languages:
//   - en: English (default)
//   - nl: Dutch

package web

// translations maps language codes to key-value translation pairs.
var translations = map[string]map[string]string{
	"en": {
		"index":                  "Index",
		"registration_complete": "Registration complete",
		"registration_complete_description_01": "Your account has been successfully verified.",
		"registration_complete_description_02": "You can now return to the SwayRider app.",
		"registration_complete_description_03": "Should the app not refresh automatically, please logout and back in again.",
		"registration_not_complete":           "Registration not complete",
		"registration_not_complete_description_01": "Your account has not been verified yet.",
		"registration_not_complete_description_02": "Check your email for a verification link.",
		"return_to_app":          "Return to SwayRider app",
		"reset_password":                        "Reset Password",
		"reset_password_description":            "Enter your new password below.",
		"reset_password_new_password":           "New Password",
		"reset_password_confirm_password":       "Confirm Password",
		"reset_password_submit":                 "Reset Password",
		"reset_password_passwords_no_match":     "Passwords do not match.",
		"reset_password_complete":               "Password Reset Successful",
		"reset_password_complete_description":   "Your password has been reset. You can now log in with your new password.",
		"reset_password_error":                  "Failed to reset password.",
		"reset_password_invalid_link":           "This reset link is invalid or has expired.",
	},
	"nl": {
		"index":                  "Index",
		"registration_complete": "Registratie voltooid",
		"registration_complete_description_01": "Uw account is succesvol geverifieerd.",
		"registration_complete_description_02": "U kunt nu terugkeren naar de SwayRider app.",
		"registration_complete_description_03": "Als de app niet automatisch ververst, log dan even uit en terug in.",
		"registration_not_complete":           "Registratie niet voltooid",
		"registration_not_complete_description_01": "Uw account is nog niet geverifieerd.",
		"registration_not_complete_description_02": "Contorleer uw e-mail voor een verificatie link.",
		"return_to_app":          "Terug naar de SwayRider app",
		"reset_password":                        "Wachtwoord Resetten",
		"reset_password_description":            "Voer hieronder uw nieuw wachtwoord in.",
		"reset_password_new_password":           "Nieuw Wachtwoord",
		"reset_password_confirm_password":       "Bevestig Wachtwoord",
		"reset_password_submit":                 "Wachtwoord Resetten",
		"reset_password_passwords_no_match":     "Wachtwoorden komen niet overeen.",
		"reset_password_complete":               "Wachtwoord Reset Geslaagd",
		"reset_password_complete_description":   "Uw wachtwoord is gereset. U kunt nu inloggen met uw nieuw wachtwoord.",
		"reset_password_error":                  "Wachtwoord resetten mislukt.",
		"reset_password_invalid_link":           "Deze resetlink is ongeldig of verlopen.",
	},
}

// translator returns a translation function for the specified language.
// Falls back to English if the language is not supported.
func translator(lang string) func(string) string {
	dict, ok := translations[lang]
	if !ok {
		dict = translations["en"]
	}
	return func(key string) string {
		if val, ok := dict[key]; ok {
			return val
		}
		return key
	}
}

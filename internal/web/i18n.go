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
		"register":                           "Create Account",
		"register_description":               "Fill in the form below to create your SwayRider account.",
		"register_email":                     "Email Address",
		"register_password":                  "Password",
		"register_confirm_password":          "Confirm Password",
		"register_submit":                    "Create Account",
		"register_email_required":            "Email address is required.",
		"register_passwords_no_match":        "Passwords do not match.",
		"register_password_too_weak":         "Password is too weak. Please use a stronger password.",
		"register_email_taken":               "An account with this email address already exists.",
		"register_not_invited":               "This email address has not been invited.",
		"register_not_invited_title":         "Invitation Required",
		"register_not_invited_description":   "This email address does not have a pending invitation.",
		"register_not_invited_details":       "SwayRider is currently invite-only. Visit our GitHub page to learn more about how to request access.",
		"register_not_invited_learn_more":    "Learn more on GitHub",
		"register_error":                     "Registration failed. Please try again.",
		"register_pending":                   "Check Your Email",
		"register_pending_description":       "Your account has been created. A verification link has been sent to your email address.",
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
		"verify_user_confirm":                   "Confirming your email",
		"verify_user_confirm_description":       "Please wait while we verify your account.",
		"verify_user_confirm_submit":            "Verify Email",
	},
	"nl": {
		"index":                  "Index",
		"register":                           "Account aanmaken",
		"register_description":               "Vul het onderstaande formulier in om uw SwayRider account aan te maken.",
		"register_email":                     "E-mailadres",
		"register_password":                  "Wachtwoord",
		"register_confirm_password":          "Bevestig wachtwoord",
		"register_submit":                    "Account aanmaken",
		"register_email_required":            "E-mailadres is vereist.",
		"register_passwords_no_match":        "Wachtwoorden komen niet overeen.",
		"register_password_too_weak":         "Wachtwoord is te zwak. Gebruik een sterker wachtwoord.",
		"register_email_taken":               "Er bestaat al een account met dit e-mailadres.",
		"register_not_invited":               "Dit e-mailadres is niet uitgenodigd.",
		"register_not_invited_title":         "Uitnodiging vereist",
		"register_not_invited_description":   "Dit e-mailadres heeft geen openstaande uitnodiging.",
		"register_not_invited_details":       "SwayRider is momenteel alleen op uitnodiging beschikbaar. Bezoek onze GitHub-pagina voor meer informatie over hoe u toegang kunt aanvragen.",
		"register_not_invited_learn_more":    "Meer info op GitHub",
		"register_error":                     "Registratie mislukt. Probeer het opnieuw.",
		"register_pending":                   "Controleer uw e-mail",
		"register_pending_description":       "Uw account is aangemaakt. Er is een verificatielink naar uw e-mailadres gestuurd.",
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
		"verify_user_confirm":                   "E-mail bevestigen",
		"verify_user_confirm_description":       "Even geduld, we verifiëren uw account.",
		"verify_user_confirm_submit":            "E-mail Verifiëren",
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

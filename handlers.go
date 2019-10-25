package main

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/julienschmidt/httprouter"
	"golang.org/x/crypto/bcrypt"

	"github.com/skip2/go-qrcode"
)

var (
	validEmail         = regexp.MustCompile(`^[ -~]+@[ -~]+$`)
	validPassword      = regexp.MustCompile(`^[ -~]{6,200}$`)
	validString        = regexp.MustCompile(`^[ -~]{1,200}$`)
	maxProfiles        = 250
	maxProfilesPerUser = 10
)

func ssoHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if token := samlSP.GetAuthorizationToken(r); token != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	logrus.Debugf("SSO: require account handler")
	samlSP.RequireAccountHandler(w, r)
	return
}

func samlHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if samlSP == nil {
		logrus.Warnf("SAML is not configured")
		http.NotFound(w, r)
		return
	}
	logrus.Debugf("SSO: samlSP.ServeHTTP")
	samlSP.ServeHTTP(w, r)
}

func wireguardQRConfigHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to view config: permission denied"))
		return
	}

	b, err := ioutil.ReadFile(profile.WireGuardConfigPath())
	if err != nil {
		Error(w.w, err)
		return
	}

	img, err := qrcode.Encode(string(b), qrcode.Medium, 256)
	if err != nil {
		Error(w.w, err)
		return
	}

	w.w.Header().Set("Content-Type", "image/png")
	w.w.Header().Set("Content-Length", fmt.Sprintf("%d", len(img)))
	if _, err := w.w.Write(img); err != nil {
		Error(w.w, err)
		return
	}
}

func wireguardConfigHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to view config: permission denied"))
		return
	}

	b, err := ioutil.ReadFile(profile.WireGuardConfigPath())
	if err != nil {
		Error(w.w, err)
		return
	}

	w.w.Header().Set("Content-Disposition", "attachment; filename="+profile.WireGuardConfigName())
	w.w.Header().Set("Content-Type", "application/x-wireguard-profile")
	w.w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
	if _, err := w.w.Write(b); err != nil {
		Error(w.w, err)
		return
	}
}

func configureHandler(w *Web) {
	if config.FindInfo().Configured {
		w.Redirect("/?error=configured")
		return
	}

	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	emailConfirm := strings.ToLower(strings.TrimSpace(w.r.FormValue("email_confirm")))
	password := w.r.FormValue("password")

	if !validEmail.MatchString(email) || !validPassword.MatchString(password) || email != emailConfirm {
		w.Redirect("/configure?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Email = email
		i.Password = hashedPassword
		i.Configured = true
		return nil
	})

	if err := w.SigninSession(true, ""); err != nil {
		Error(w.w, err)
		return
	}
	w.Redirect("/settings?success=configured")
	return
}

func forgotHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	secret := w.r.FormValue("secret")
	password := w.r.FormValue("password")

	if email != "" && !validEmail.MatchString(email) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if secret != "" && !validString.MatchString(secret) {
		w.Redirect("/forgot?error=invalid")
		return
	}
	if email != "" && secret != "" && !validPassword.MatchString(password) {
		w.Redirect("/forgot?error=invalid&email=%s&secret=%s", email, secret)
		return
	}

	if email != config.FindInfo().Email {
		w.Redirect("/forgot?error=invalid")
		return
	}

	if secret == "" {
		secret = config.FindInfo().Secret
		if secret == "" {
			secret = RandomString(32)
			config.UpdateInfo(func(i *Info) error {
				if i.Secret == "" {
					i.Secret = secret
				}
				return nil
			})
		}

		go func() {
			if err := mailer.Forgot(email, secret); err != nil {
				logrus.Error(err)
			}
		}()

		w.Redirect("/forgot?success=forgot")
		return
	}

	if secret != config.FindInfo().Secret {
		w.Redirect("/forgot?error=invalid")
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		w.Redirect("/forgot?error=bcrypt")
		return
	}
	config.UpdateInfo(func(i *Info) error {
		i.Password = hashedPassword
		i.Secret = ""
		return nil
	})

	if err := w.SigninSession(true, ""); err != nil {
		Error(w.w, err)
		return
	}
	w.Redirect("/")
	return
}

func signoutHandler(w *Web) {
	w.SignoutSession()
	w.Redirect("/signin")
}

func signinHandler(w *Web) {
	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	password := w.r.FormValue("password")

	if email != config.FindInfo().Email {
		w.Redirect("/signin?error=invalid")
		return
	}

	if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(password)); err != nil {
		w.Redirect("/signin?error=invalid")
		return
	}
	if err := w.SigninSession(true, ""); err != nil {
		Error(w.w, err)
		return
	}

	w.Redirect("/")
}

func userEditHandler(w *Web) {
	userID := w.ps.ByName("user")
	if userID == "" {
		userID = w.r.FormValue("user")
	}
	user, err := config.FindUser(userID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin {
		Error(w.w, fmt.Errorf("failed to edit user: permission denied"))
		return
	}

	if w.r.Method == "GET" {
		w.TargetUser = user
		w.Profiles = config.ListProfilesByUser(user.ID)
		w.HTML()
		return
	}

	if w.User.ID == user.ID {
		w.Redirect("/user/edit/%s", user.ID)
		return
	}

	admin := w.r.FormValue("admin") == "yes"

	config.UpdateUser(user.ID, func(u *User) error {
		u.Admin = admin
		return nil
	})

	w.Redirect("/user/edit/%s?success=edituser", user.ID)
}

func userDeleteHandler(w *Web) {
	userID := w.ps.ByName("user")
	if userID == "" {
		userID = w.r.FormValue("user")
	}
	user, err := config.FindUser(userID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin {
		Error(w.w, fmt.Errorf("failed to delete user: permission denied"))
		return
	}
	if w.User.ID == user.ID {
		w.Redirect("/user/edit/%s?error=deleteuser", user.ID)
		return
	}

	if w.r.Method == "GET" {
		w.TargetUser = user
		w.HTML()
		return
	}

	for _, profile := range config.ListProfilesByUser(user.ID) {
		if err := deleteProfile(profile); err != nil {
			logrus.Errorf("delete profile failed: %s", err)
			w.Redirect("/profile/delete?error=deleteprofile")
			return
		}
	}

	if err := config.DeleteUser(user.ID); err != nil {
		Error(w.w, err)
		return
	}
	w.Redirect("/?success=deleteuser")
}

func profileAddHandler(w *Web) {
	if !w.Admin && w.User.ID == "" {
		http.NotFound(w.w, w.r)
		return
	}

	name := strings.TrimSpace(w.r.FormValue("name"))
	platform := strings.TrimSpace(w.r.FormValue("platform"))
	admin := w.r.FormValue("admin") == "yes"

	if platform == "" {
		platform = "other"
	}

	if name == "" {
		w.Redirect("/?error=profilename")
		return
	}

	var userID string
	if admin {
		userID = ""
	} else {
		userID = w.User.ID
	}

	if !admin {
		if len(config.ListProfilesByUser(userID)) >= maxProfilesPerUser {
			w.Redirect("/?error=addprofile")
			return
		}
	}

	if len(config.ListProfiles()) >= maxProfiles {
		w.Redirect("/?error=addprofile")
		return
	}

	profile, err := config.AddProfile(userID, name, platform)
	if err != nil {
		logrus.Warn(err)
		w.Redirect("/?error=addprofile")
		return
	}

	_, ipNet, err := net.ParseCIDR(clientIPv4Subnet)
	if err != nil {
		logrus.Warn(err)
		w.Redirect("/?error=addprofile")
		return
	}

	mask, _ := ipNet.Mask.Size()

	subnetSplit := strings.Split(clientIPv4Subnet, ".")
	newAddr := fmt.Sprintf("%s.%s.%s.%d", subnetSplit[0], subnetSplit[1], subnetSplit[2], profile.Number)

	_, err = bash("create_profile.shell", struct {
		DataDir              string
		Profile              Profile
		Domain               string
		WireguardPort        int
		NewAddress           string
		NewAddressMask       int
		ClientIPv4Subnet     string
		ClientIPv4DNS        string
		ClientUseIPv4DNS     bool
		ClientIPv4Gateway    string
		ClientIPv4UseGateway bool
		ClientIPv6Enabled    bool
		ClientIPv6Subnet     string
		ClientIPv6DNS        string
		ClientIPv6UseDNS     bool
		ClientIPv6Gateway    string
		ClientIPv6UseGateway bool
		ClientKeepAlive      int
	}{
		datadir,
		profile,
		httpHost,
		wireguardPort,
		newAddr,
		mask,
		clientIPv4Subnet,
		clientIPv4DNS,
		clientIPv4UseDNS,
		clientIPv4Gateway,
		clientIPv4UseGateway,
		clientIPv6Enabled,
		clientIPv6Subnet,
		clientIPv6DNS,
		clientIPv6UseDNS,
		clientIPv6Gateway,
		clientIPv6UseGateway,
		clientKeepAlive,
	})
	if err != nil {
		logrus.Warn(err)
		w.Redirect("/?error=addprofile")
		return
	}

	w.Redirect("/profile/connect/%s?success=addprofile", profile.ID)
}

func profileConnectHandler(w *Web) {
	profile, err := config.FindProfile(w.ps.ByName("profile"))
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to view profile: permission denied"))
		return
	}
	w.Profile = profile
	w.HTML()
	return
}

func profileDeleteHandler(w *Web) {
	profileID := w.ps.ByName("profile")
	if profileID == "" {
		profileID = w.r.FormValue("profile")
	}
	profile, err := config.FindProfile(profileID)
	if err != nil {
		http.NotFound(w.w, w.r)
		return
	}
	if !w.Admin && profile.UserID != w.User.ID {
		Error(w.w, fmt.Errorf("failed to delete profile: permission denied"))
		return
	}

	if w.r.Method == "GET" {
		w.Profile = profile
		w.HTML()
		return
	}
	if err := deleteProfile(profile); err != nil {
		logrus.Errorf("delete profile failed: %s", err)
		w.Redirect("/profile/delete?error=deleteprofile")
		return
	}
	if profile.UserID != "" {
		w.Redirect("/user/edit/%s?success=deleteprofile", profile.UserID)
		return
	}
	w.Redirect("/?success=deleteprofile")
}

func indexHandler(w *Web) {
	if w.User.ID != "" {
		w.TargetProfiles = config.ListProfilesByUser(w.User.ID)
	}
	if w.Admin {
		w.Profiles = config.ListProfilesByUser("")
		w.Users = config.ListUsers()
	} else {
		w.Profiles = config.ListProfilesByUser(w.User.ID)
	}
	w.HTML()
}

func settingsHandler(w *Web) {
	if !w.Admin {
		Error(w.w, fmt.Errorf("settings: permission denied"))
		return
	}

	if w.r.Method == "GET" {
		w.HTML()
		return
	}

	email := strings.ToLower(strings.TrimSpace(w.r.FormValue("email")))
	samlMetadata := strings.TrimSpace(w.r.FormValue("saml_metadata"))

	currentPassword := w.r.FormValue("current_password")
	newPassword := w.r.FormValue("new_password")

	config.UpdateInfo(func(i *Info) error {
		i.SAML.IDPMetadata = samlMetadata
		i.Email = email
		return nil
	})

	// Configure SAML if metadata is present.
	if len(samlMetadata) > 0 {
		if err := configureSAML(); err != nil {
			logrus.Warnf("configuring SAML failed: %s", err)
			w.Redirect("/settings?error=saml")
		}
	} else {
		samlSP = nil
	}

	if currentPassword != "" || newPassword != "" {
		if !validPassword.MatchString(newPassword) {
			w.Redirect("/settings?error=invalid")
			return
		}

		if err := bcrypt.CompareHashAndPassword(config.FindInfo().Password, []byte(currentPassword)); err != nil {
			w.Redirect("/settings?error=invalid")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			w.Redirect("/settings?error=bcrypt")
			return
		}

		config.UpdateInfo(func(i *Info) error {
			i.Password = hashedPassword
			return nil
		})
	}

	w.Redirect("/settings?success=settings")
}

func helpHandler(w *Web) {
	w.HTML()
}

//
// Helpers
//
func deleteProfile(profile Profile) error {
	output, err := bash("delete_profile.shell", struct {
		DataDir string
		Profile Profile
	}{
		datadir,
		profile,
	})
	if err != nil {
		return fmt.Errorf("delete profile failed %s %s", err, output)
	}
	return config.DeleteProfile(profile.ID)
}

func shellTemplate(name string) (*template.Template, error) {
	for _, filename := range AssetNames() {
		if !strings.HasPrefix(filename, "shell/") {
			continue
		}
		templateName := strings.TrimPrefix(filename, "shell/")
		if name != templateName {
			continue
		}

		templateData, err := Asset(filename)
		if err != nil {
			return nil, fmt.Errorf("failed to load asset: %s - %w", filename, err)
		}

		tmpl := template.New(templateName)
		if _, err := tmpl.Parse(string(templateData)); err != nil {
			return nil, fmt.Errorf("failed to parse template: %s - template: %s %w", filename, string(templateData), err)
		}
		return tmpl, nil
	}
	return nil, fmt.Errorf("couldn't find template for %s", name)
}

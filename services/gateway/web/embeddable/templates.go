package embeddable

import (
	"embed"
	"encoding/json"
	"text/template"

	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

//go:embed templates
var templateFiles embed.FS

//go:embed locales
var localeFiles embed.FS

//go:embed images
var IconFiles embed.FS

var (
	Bundle     = i18n.NewBundle(language.English)
	EditorPage = template.Must(template.ParseFS(
		templateFiles, "templates/editor.html", "templates/spinner.html",
	))
	ErrorPage             = template.Must(template.ParseFS(templateFiles, "templates/error.html"))
	InstallationErrorPage = template.Must(template.ParseFS(templateFiles, "templates/installation.html"))
	ConvertPage           = template.Must(template.ParseFS(
		templateFiles, "templates/convert.html", "templates/error.html", "templates/spinner.html",
	))
)

func init() {
	Bundle.RegisterUnmarshalFunc("json", json.Unmarshal)
	emsg, err := Bundle.LoadMessageFileFS(localeFiles, "locales/en.json")
	if err != nil {
		panic(err)
	}

	Bundle.MustAddMessages(emsg.Tag, emsg.Messages...)

	rmsg, err := Bundle.LoadMessageFileFS(localeFiles, "locales/ru.json")
	if err != nil {
		panic(err)
	}

	Bundle.MustAddMessages(emsg.Tag, rmsg.Messages...)
}

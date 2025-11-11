/**
 *
 * (c) Copyright Ascensio System SIA 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
	EmailPage = template.Must(template.ParseFS(
		templateFiles, "templates/email.html",
	))
	DesktopPage = template.Must(template.ParseFS(
		templateFiles, "templates/desktop.html",
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

	Bundle.MustAddMessages(rmsg.Tag, rmsg.Messages...)

	dmsg, err := Bundle.LoadMessageFileFS(localeFiles, "locales/de.json")
	if err != nil {
		panic(err)
	}

	Bundle.MustAddMessages(dmsg.Tag, dmsg.Messages...)

	esmsg, err := Bundle.LoadMessageFileFS(localeFiles, "locales/es.json")
	if err != nil {
		panic(err)
	}

	Bundle.MustAddMessages(esmsg.Tag, esmsg.Messages...)

	frmsg, err := Bundle.LoadMessageFileFS(localeFiles, "locales/fr.json")
	if err != nil {
		panic(err)
	}

	Bundle.MustAddMessages(frmsg.Tag, frmsg.Messages...)

	itmsg, err := Bundle.LoadMessageFileFS(localeFiles, "locales/it.json")
	if err != nil {
		panic(err)
	}

	Bundle.MustAddMessages(itmsg.Tag, itmsg.Messages...)

	jmsg, err := Bundle.LoadMessageFileFS(localeFiles, "locales/ja.json")
	if err != nil {
		panic(err)
	}

	Bundle.MustAddMessages(jmsg.Tag, jmsg.Messages...)

	ptmsg, err := Bundle.LoadMessageFileFS(localeFiles, "locales/pt-BR.json")
	if err != nil {
		panic(err)
	}

	Bundle.MustAddMessages(ptmsg.Tag, ptmsg.Messages...)

	zmsg, err := Bundle.LoadMessageFileFS(localeFiles, "locales/zh.json")
	if err != nil {
		panic(err)
	}

	Bundle.MustAddMessages(zmsg.Tag, zmsg.Messages...)
}

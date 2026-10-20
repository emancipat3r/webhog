package renderer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/go-rod/rod"
)

// stateGlobals are the window properties single-page frameworks use to hand
// server state and runtime configuration to the client. They are read as
// JSON after the page settles; whatever the app put there is scanned like
// a script.
var stateGlobals = []string{
	"__NEXT_DATA__", "__NUXT__", "__INITIAL_STATE__", "__PRELOADED_STATE__", "__APOLLO_STATE__",
	"__APP_CONFIG__", "__CONFIG__", "__ENV__", "__env__", "ENV", "env", "config", "appConfig",
	"APP_CONFIG", "runtimeConfig", "__RUNTIME_CONFIG__", "_env_", "__SETTINGS__", "settings",
	"firebaseConfig", "__FIREBASE_DEFAULTS__", "dataLayer", "__sentryConfig",
}

// stateScript dumps the storages and the known globals as one JSON object.
// Values that are not serialisable (functions, cycles) are skipped.
const stateScript = `(names) => {
	const out = {localStorage: {}, sessionStorage: {}, globals: {}};
	const dump = (store, into) => {
		try {
			for (let i = 0; i < store.length; i++) {
				const k = store.key(i);
				into[k] = store.getItem(k);
			}
		} catch (e) {}
	};
	try { dump(window.localStorage, out.localStorage); } catch (e) {}
	try { dump(window.sessionStorage, out.sessionStorage); } catch (e) {}
	for (const n of names) {
		try {
			const v = window[n];
			if (v === undefined || v === null || typeof v === 'function') continue;
			const s = typeof v === 'string' ? v : JSON.stringify(v);
			if (s && s !== '{}' && s !== '[]') out.globals[n] = s;
		} catch (e) {}
	}
	return out;
}`

type pageState struct {
	LocalStorage   map[string]string `json:"localStorage"`
	SessionStorage map[string]string `json:"sessionStorage"`
	Globals        map[string]string `json:"globals"`
}

// capturedState reads the page's storages, cookies and framework globals
// into blobs with Source "state". Their paths are the page URL with a
// fragment naming the store, so a finding says where the value lives.
// Capture is best-effort: a page that blocks storage access yields nothing.
func capturedState(page *rod.Page, pageURL string) []JSBlob {
	var blobs []JSBlob
	res, err := page.Eval(stateScript, stateGlobals)
	if err == nil && res != nil {
		var st pageState
		if json.Unmarshal([]byte(res.Value.JSON("", "")), &st) == nil {
			if b := kvBlob(pageURL+"#localStorage", st.LocalStorage); b != nil {
				blobs = append(blobs, *b)
			}
			if b := kvBlob(pageURL+"#sessionStorage", st.SessionStorage); b != nil {
				blobs = append(blobs, *b)
			}
			keys := make([]string, 0, len(st.Globals))
			for k := range st.Globals {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				blobs = append(blobs, JSBlob{Source: "state", Path: pageURL + "#window." + k, Body: st.Globals[k], Status: 200})
			}
		}
	}
	// Cookies come from the browser, HttpOnly ones included, which
	// document.cookie would hide.
	if cookies, err := page.Cookies(nil); err == nil && len(cookies) > 0 {
		var sb strings.Builder
		for _, c := range cookies {
			flags := ""
			if c.HTTPOnly {
				flags += " HttpOnly"
			}
			if c.Secure {
				flags += " Secure"
			}
			fmt.Fprintf(&sb, "%s=%s; Domain=%s; Path=%s;%s\n", c.Name, c.Value, c.Domain, c.Path, flags)
		}
		blobs = append(blobs, JSBlob{Source: "state", Path: pageURL + "#cookies", Body: sb.String(), Status: 200})
	}
	return blobs
}

// kvBlob renders a storage as one line per key, or nil when empty.
func kvBlob(path string, kv map[string]string) *JSBlob {
	if len(kv) == 0 {
		return nil
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&sb, "%s=%s\n", k, kv[k])
	}
	return &JSBlob{Source: "state", Path: path, Body: sb.String(), Status: 200}
}

package engine

import (
	"context"
	"encoding/json"
	"net/url"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

func (p *browserbaseProvider) CreateRuntimeSession(ctx context.Context, profile BrowserProfile) (string, string, error) {
	u, err := url.Parse(profile.WebsiteURL)
	if err != nil || !validBrowserProfile(profile) || profile.ConfigurationID != p.ConfigurationID() {
		return "", "", errBrowserSignIn
	}
	var out struct {
		ID         string `json:"id"`
		ProjectID  string `json:"projectId"`
		ContextID  string `json:"contextId"`
		ConnectURL string `json:"connectUrl"`
	}
	err = p.request(ctx, "POST", "/sessions", map[string]any{"projectId": p.config.ProjectID, "timeout": 600, "keepAlive": true, "proxies": false, "browserSettings": map[string]any{"context": map[string]any{"id": profile.ProfileID, "persist": false}, "allowedDomains": []string{u.Hostname()}, "recordSession": false, "logSession": false, "solveCaptchas": false, "advancedStealth": false, "verified": false, "viewport": map[string]int{"width": 1280, "height": 800}}}, &out, false)
	if err != nil || !browserResourceID(out.ID) || out.ProjectID != p.config.ProjectID || out.ContextID != profile.ProfileID {
		return "", "", errBrowserSignIn
	}
	// Return the allocated ID even if its private transport URL is invalid, so
	// the caller can checkpoint and stop it without losing cleanup authority.
	return out.ID, out.ConnectURL, nil
}

type browserCDP struct {
	conn    *websocket.Conn
	next    int
	session string
}

func (c *browserCDP) call(ctx context.Context, method string, params any, out any) error {
	c.next++
	request := map[string]any{"id": c.next, "method": method, "params": params}
	if c.session != "" {
		request["sessionId"] = c.session
	}
	if wsjson.Write(ctx, c.conn, request) != nil {
		return errBrowserSignIn
	}
	for range 1000 {
		var msg struct {
			ID     int             `json:"id"`
			Error  json.RawMessage `json:"error"`
			Result json.RawMessage `json:"result"`
		}
		if wsjson.Read(ctx, c.conn, &msg) != nil {
			return errBrowserSignIn
		}
		if msg.ID != c.next {
			continue
		}
		if len(msg.Error) > 0 || json.Unmarshal(msg.Result, out) != nil {
			return errBrowserSignIn
		}
		return nil
	}
	return errBrowserSignIn
}
func (c *browserCDP) evaluate(ctx context.Context, world int, expression string, out any) error {
	var result struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		Exception json.RawMessage `json:"exceptionDetails"`
	}
	if c.call(ctx, "Runtime.evaluate", map[string]any{"expression": expression, "contextId": world, "returnByValue": true, "awaitPromise": false}, &result) != nil || len(result.Exception) > 0 || json.Unmarshal(result.Result.Value, out) != nil {
		return errBrowserSignIn
	}
	return nil
}

func (p *browserbaseProvider) BrowserAction(ctx context.Context, connect, website string, action BrowserAction) (*BrowserSnapshot, error) {
	if !browserbaseURL(connect, "wss") || !browserActionValid(action, website) {
		return nil, errBrowserSignIn
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, connect, &websocket.DialOptions{HTTPClient: p.client})
	if err != nil {
		return nil, errBrowserSignIn
	}
	defer conn.CloseNow()
	conn.SetReadLimit(256 << 10)
	c := &browserCDP{conn: conn}
	var targets struct {
		Infos []struct {
			ID   string `json:"targetId"`
			Type string `json:"type"`
		} `json:"targetInfos"`
	}
	if c.call(ctx, "Target.getTargets", map[string]any{}, &targets) != nil {
		return nil, errBrowserSignIn
	}
	target := ""
	for _, t := range targets.Infos {
		if t.Type == "page" {
			target = t.ID
			break
		}
	}
	if target == "" {
		var created struct {
			ID string `json:"targetId"`
		}
		if c.call(ctx, "Target.createTarget", map[string]string{"url": "about:blank"}, &created) != nil {
			return nil, errBrowserSignIn
		}
		target = created.ID
	}
	var attached struct {
		ID string `json:"sessionId"`
	}
	if c.call(ctx, "Target.attachToTarget", map[string]any{"targetId": target, "flatten": true}, &attached) != nil || attached.ID == "" {
		return nil, errBrowserSignIn
	}
	c.session = attached.ID
	if action.Operation == "open" || action.Operation == "navigate" {
		dest := action.URL
		if action.Operation == "open" {
			dest = website
		}
		var nav struct {
			Error string `json:"errorText"`
		}
		if c.call(ctx, "Page.navigate", map[string]string{"url": dest}, &nav) != nil || nav.Error != "" {
			return nil, errBrowserSignIn
		}
		return nil, nil
	}
	var tree struct {
		Tree struct {
			Frame struct {
				ID  string `json:"id"`
				URL string `json:"url"`
			} `json:"frame"`
		} `json:"frameTree"`
	}
	if c.call(ctx, "Page.getFrameTree", map[string]any{}, &tree) != nil || browserOrigin(tree.Tree.Frame.URL) != browserOrigin(website) {
		return nil, errBrowserSignIn
	}
	var world struct {
		ID int `json:"executionContextId"`
	}
	if c.call(ctx, "Page.createIsolatedWorld", map[string]any{"frameId": tree.Tree.Frame.ID, "worldName": "synaxis-browser-runtime"}, &world) != nil || world.ID == 0 {
		return nil, errBrowserSignIn
	}
	// Only these fixed scripts run. Page scripts cannot read the isolated-world
	// element references, and model text is JSON encoded, never evaluated.
	if action.Operation == "snapshot" {
		id, _ := json.Marshal("snap_" + newEpoch())
		var snapshot BrowserSnapshot
		script := `(()=>{const nodes=[...document.querySelectorAll('a,button,input,textarea,select,[role="button"],[contenteditable="true"]')].filter(e=>e.getClientRects().length && !e.disabled && e.type!=='password' && e.type!=='hidden' && e.type!=='file').slice(0,200);const id=` + string(id) + `;globalThis.__synaxis={id,nodes,html:nodes.map(e=>e.outerHTML)};return {id,url:location.href,title:document.title.slice(0,300),text:(document.body?.innerText||'').slice(0,16000),elements:nodes.map((e,i)=>({id:i+1,role:e.getAttribute('role')||e.tagName.toLowerCase(),label:(e.getAttribute('aria-label')||e.innerText||e.getAttribute('placeholder')||e.getAttribute('name')||'').slice(0,200)}))}})()`
		if c.evaluate(ctx, world.ID, script, &snapshot) != nil || browserOrigin(snapshot.URL) != browserOrigin(website) || !boundBrowserSnapshot(&snapshot) {
			return nil, errBrowserSignIn
		}
		return &snapshot, nil
	}
	if action.Operation == "scroll" {
		var ok bool
		err = c.evaluate(ctx, world.ID, `(()=>{window.scrollBy(0,700);return true})()`, &ok)
		return nil, err
	}
	raw, _ := json.Marshal(action)
	// Nodes must still be the exact connected DOM objects from the approved
	// snapshot, with unchanged markup. A stale/different page cannot receive it.
	script := `(()=>{const a=` + string(raw) + `;const s=globalThis.__synaxis,e=s?.nodes[a.element-1];if(!s||s.id!==a.snapshot||!e||!e.isConnected||e.outerHTML!==s.html[a.element-1]||e.type==='password'||e.type==='file')return false;if(a.operation==='click'){e.click()}else{if(a.operation==='type' && !(e.tagName==='INPUT'||e.tagName==='TEXTAREA'||e.isContentEditable))return false;e.focus();if(a.operation==='type'){if(e.select)e.select();else{const r=document.createRange();r.selectNodeContents(e);const sel=getSelection();sel.removeAllRanges();sel.addRange(r)}}}return true})()`
	var ok bool
	if c.evaluate(ctx, world.ID, script, &ok) != nil || !ok {
		return nil, errBrowserSignIn
	}
	if action.Operation == "type" {
		err = c.call(ctx, "Input.insertText", map[string]string{"text": action.Text}, &struct{}{})
	}
	if action.Operation == "press" {
		keyCode := map[string]int{"Enter": 13, "Tab": 9, "Escape": 27}[action.Key]
		for _, typ := range []string{"keyDown", "keyUp"} {
			if err = c.call(ctx, "Input.dispatchKeyEvent", map[string]any{"type": typ, "key": action.Key, "code": action.Key, "windowsVirtualKeyCode": keyCode}, &struct{}{}); err != nil {
				break
			}
		}
	}
	return nil, err
}

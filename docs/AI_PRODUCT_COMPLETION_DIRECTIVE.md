# KernAid AI product-completion directive

> Prepared continuation directive. Execution is paused after the current
> diagnosis-release/site/documentation closeout, as explicitly requested by
> the owner; paste this directive to resume the remaining product work.

Portare KernAid dall'attuale release candidate a un prodotto software completo
nelle due edizioni Consumer ed Enterprise entro un massimo di sette giorni
attivi di elaborazione AI.

Procedere autonomamente, code-first e con più agenti in parallelo su stream
indipendenti. Dare priorità nell'ordine a:

1. qualificare, promuovere e pubblicare immediatamente sul sito l'ultima ISO
   diagnosis-only, con checksum, catalogo trusted e percorso Windows di
   scrittura USB coerenti;
2. completare il flusso Consumer guidato Rescue/Desk: avvio, diagnosi offline,
   Vault, provider opzionale, spiegazione semplice, report, Media Creator e
   recovery;
3. qualificare e promuovere i repair pack chiusi con target binding, backup,
   approvazione locale, verifica e rollback;
4. chiudere il ciclo Enterprise: onboarding, Resident multipiattaforma,
   identità, policy restrittiva, licensing, work order, approvazione locale,
   risultato firmato, incidenti, audit e aggiornamento A/B;
5. completare i percorsi nativi Windows e macOS e il WinPE Companion
   customer-buildable nei limiti consentiti dalla licenza Microsoft;
6. pubblicare artefatti, documentazione operativa e sito commerciale/privato
   coerenti con lo stesso commit e con evidenza di qualifica esatta.

Regole di esecuzione:

- usare esattamente Node.js `24.18.0`;
- implementare in batch verticali sostanziali; non creare una build ISO per
  ogni micro-modifica;
- durante lo sviluppo eseguire soltanto syntax/static check e test direttamente
  interessati dalla modifica;
- aggregare boot, UI, Vault e repair in una sola matrice per milestone e
  riutilizzare ogni evidenza verde il cui codice/input non sia cambiato;
- privilegiare sviluppo e integrazione rispetto a suite ripetute o diagnostica
  speculativa, senza indebolire i confini fail-closed di target, evidenza,
  approvazione, backup, verifica e rollback;
- assegnare agenti separati a Consumer, Repair, Enterprise, release e sito;
  integrare appena un batch è revisionato, senza attendere gli altri stream;
- fare add/commit/push progressivi su `0xfunboy/KernAid`, branch `main`, come
  `0xfunboy <0xfunboy@gmail.com>`;
- mantenere documentazione, catalogo e sito aggiornati ad ogni promozione;
- non fermarsi per chiedere decisioni già determinabili dal repository;
  avvisare l'utente soltanto a prodotto realmente finito o quando serve un
  intervento esterno indispensabile.

USB fisica, firmware rappresentativi, credenziali provider reali,
Authenticode, Developer ID/notarizzazione e hardware realmente guasto sono
gate esterni da tracciare e richiedere quando diventano l'ultimo blocco; non
devono sospendere lo sviluppo software parallelo. KernAid può diagnosticare un
guasto fisico e guidare isolamento, recupero o sostituzione, ma non deve
affermare di riparare via software un componente materialmente rotto.

Definition of done: download Consumer utilizzabile, Desk installabile sui
sistemi dichiarati, repair abilitati solo se qualificati, ciclo Enterprise
end-to-end operativo, sito e documentazione allineati, artefatti riproducibili
e un elenco breve dei soli gate esterni ancora non eseguibili senza hardware o
credenziali dell'utente.

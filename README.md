# sslcheck
SSL-checker

# installatie
Kan niet in een docker image omdat dig gebruikt wordt.

run-versie staat in /opt/sslcheck

# secret
Om een andere apikey dan `MySecret` te gebruiken zet dan het volgende in een bestand met de naam `.env`:
`SECRETAPIKEY=<apikey>`. Dit bestand wordt gelezen bij opstarten, dus na wijzigen moet de applicatie herstart worden.

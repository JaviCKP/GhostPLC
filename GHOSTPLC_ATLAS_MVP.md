# GhostPLC Atlas MVP

## Resumen

La arquitectura queda en dos piezas:

```text
ghostplc-sensor     -> VM Ubuntu en Google Cloud Compute Engine
ghostplc-dashboard  -> Next.js en Vercel
```

Google Cloud expone honeypots y captura eventos. Vercel solo consulta una API con eventos anonimizados y los muestra.

Configuracion objetivo:

```text
Proveedor: Google Cloud
Uso: Free Trial con $300 de credito
VM: e2-medium para MVP, e2-standard-2 si quieres mas margen
Sistema: Ubuntu 22.04 LTS
Disco: 50 GB
IP publica: si, mejor estatica
Network tag: ghostplc-sensor
```

Cambios importantes frente a la version OCI:

1. Las VM `e2-*` de Google Cloud son x86_64, asi que puedes usar `honeynet/conpot:latest` directamente. El build local de Conpot queda solo como fallback para ARM64.
2. En Google Cloud tienes que abrir puertos con reglas de VPC Firewall y aplicarlas a la VM con un network tag.
3. En Ubuntu de Google Cloud normalmente no existe la trampa de `iptables` preconfigurado de OCI, pero dejo un script de firewall Linux opcional si activas `ufw`/`iptables` o quieres dejarlo explicitamente abierto tambien dentro del SO.
4. Cowrie en `2222` esta bien para MVP. Para capturar mucho ruido real de SSH, la iteracion de produccion debe redirigir `22 -> 2222` con `iptables` despues de mover el SSH real a `50022`.
5. El almacenamiento principal es SQLite. La API expone JSON bajo demanda.
6. Hay analisis narrativo opcional con OpenAI `gpt-5-nano`, pensado para que GhostPLC vaya contando tendencias y rarezas con voz propia sin mandar IPs reales.

Referencias:

- Google Cloud Free Trial: <https://docs.cloud.google.com/free/docs/free-cloud-features>
- Compute Engine E2: <https://docs.cloud.google.com/compute/docs/general-purpose-machines>
- Google Cloud VPC Firewall: <https://docs.cloud.google.com/firewall/docs/firewalls>
- Conpot Docker: <https://conpot.readthedocs.io/en/latest/installation/quick_install.html>
- Cowrie Docker: <https://docs.cowrie.org/en/latest/docker/README.html>
- Vercel Next.js: <https://vercel.com/docs/frameworks/full-stack/nextjs>
- OpenAI `gpt-5-nano`: <https://platform.openai.com/docs/models/gpt-5-nano>
- OpenAI Responses API: <https://platform.openai.com/docs/api-reference/responses>

## Estructura creada

```text
C:\GhostPLC
  GHOSTPLC_ATLAS_MVP.md
  ghostplc-sensor/
    docker-compose.yml
    .env.example
    collector/
      __init__.py
      api.py
      analyzer.py
      collector.py
      requirements.txt
      storage.py
    tests/
      test_collector_pipeline.py
    scripts/
      build-conpot-image.sh
      configure-linux-firewall.sh
      configure-oci-firewall.sh
      create-gcp-firewall-rules.sh
      enable-cowrie-port22-redirect.sh
      install-systemd.sh
      smoke-test-local.sh
    systemd/
      ghostplc-api.service
      ghostplc-collector.service
      ghostplc-collector.timer
      ghostplc-analyzer.service
      ghostplc-analyzer.timer
  ghostplc-dashboard/
    src/app/page.tsx
    src/app/api/events/route.ts
    .env.example
```

## Paso 1: crear la VM en Google Cloud

Crea una instancia de Compute Engine:

```text
Name: ghostplc-sensor
Machine type: e2-medium o e2-standard-2
Boot disk: Ubuntu 22.04 LTS
Disk size: 50 GB
External IPv4: habilitada
Network tag: ghostplc-sensor
```

Recomendacion: reserva una IP externa estatica y asignala a la VM. Vercel va a apuntar a esa IP; si dejas una IP efimera, puede cambiar al parar/recrear la instancia.

## Paso 2: abrir firewall en Google Cloud

Abre estos puertos con reglas de VPC Firewall aplicadas al tag `ghostplc-sensor`:

```text
22/tcp      solo tu IP, SSH administrativo del MVP
80/tcp      publico, Conpot HTTP industrial
102/tcp     publico, Conpot S7 falso
502/tcp     publico, Conpot Modbus falso
161/udp     publico, Conpot SNMP falso
2222/tcp    publico, Cowrie SSH honeypot para MVP
2223/tcp    publico, Cowrie Telnet honeypot opcional
8088/tcp    publico, API GhostPLC con bearer token
```

Para la iteracion de produccion con Cowrie en el puerto 22, mas adelante abre tambien:

```text
50022/tcp   solo tu IP, nuevo SSH administrativo
22/tcp      publico, redirigido a Cowrie
```

No hagas el cambio de `22 -> Cowrie` hasta completar el MVP y verificar que puedes entrar por `50022`.

### Opcion CLI

Si tienes `gcloud` configurado en tu PC:

```bash
cd ghostplc-sensor
ADMIN_CIDR=TU_IP_PUBLICA/32 ./scripts/create-gcp-firewall-rules.sh
```

El script crea:

```text
ghostplc-allow-admin     tcp:22,tcp:50022 desde ADMIN_CIDR
ghostplc-allow-honeypots tcp:80,tcp:102,tcp:502,tcp:2222,tcp:2223,tcp:8088,udp:161 desde 0.0.0.0/0
```

La VM debe tener el network tag:

```bash
gcloud compute instances add-tags ghostplc-sensor --zone TU_ZONA --tags ghostplc-sensor
```

## Paso 3: entrar por SSH

Puedes usar la consola web de Google Cloud o:

```bash
gcloud compute ssh ghostplc-sensor --zone TU_ZONA
```

Si prefieres SSH directo, usa el usuario que hayas configurado en las llaves SSH de Google Cloud:

```bash
ssh TU_USUARIO@TU_IP_GCP
```

En esta guia, `TU_USUARIO` es el usuario Linux real con el que has entrado en la VM. El instalador de systemd usa ese usuario automaticamente, asi que ya no dependemos de que se llame `ubuntu`.

## Paso 4: preparar Ubuntu

En la VM:

```bash
sudo apt update
sudo apt install -y docker.io docker-compose-plugin git python3-venv python3-pip sqlite3 netcat-openbsd
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Sal y vuelve a entrar para que se aplique el grupo `docker`:

```bash
exit
gcloud compute ssh ghostplc-sensor --zone TU_ZONA
```

## Paso 5: subir el sensor a Google Cloud

Desde tu PC, en `C:\GhostPLC`:

```powershell
scp -r .\ghostplc-sensor TU_USUARIO@TU_IP_GCP:~/
```

Tambien puedes subirlo por `gcloud compute scp`:

```bash
gcloud compute scp --recurse ghostplc-sensor ghostplc-sensor:~/ --zone TU_ZONA
```

En la VM:

```bash
cd ~/ghostplc-sensor
cp .env.example .env
TOKEN="$(openssl rand -hex 32)"
sed -i "s/change-this-to-a-long-random-token/$TOKEN/" .env
echo "$TOKEN"
```

Guarda ese token. Lo usaras en Vercel como `SENSOR_API_TOKEN`.

Opcional: si has tocado `ufw`/`iptables` dentro de la VM y quieres abrir explicitamente tambien el firewall del sistema operativo:

```bash
chmod +x scripts/configure-linux-firewall.sh
sudo ./scripts/configure-linux-firewall.sh
```

En Google Cloud, lo normal es que baste con VPC Firewall. Este paso opcional existe por si endureces el host.

## Paso 6: arrancar honeypots

En Google Cloud `e2-*` no hace falta construir Conpot:

```bash
cd ~/ghostplc-sensor
docker compose pull
docker compose up -d
docker ps
```

Si algun dia vuelves a ARM64, cambia en `.env`:

```text
CONPOT_IMAGE=conpot:latest
```

y construye:

```bash
chmod +x scripts/build-conpot-image.sh
./scripts/build-conpot-image.sh
```

Pruebas locales:

```bash
curl http://localhost
nc -vz localhost 502
nc -vz localhost 102
```

Pruebas externas desde tu PC:

```powershell
curl.exe http://TU_IP_GCP
Test-NetConnection TU_IP_GCP -Port 80
Test-NetConnection TU_IP_GCP -Port 502
Test-NetConnection TU_IP_GCP -Port 102
Test-NetConnection TU_IP_GCP -Port 2222
Test-NetConnection TU_IP_GCP -Port 8088
ssh -p 2222 root@TU_IP_GCP
```

Usa contrasenas falsas cuando pruebes Cowrie. No escribas una contrasena real en un honeypot.

Si las pruebas locales en la VM funcionan pero estas pruebas externas dan timeout, el problema casi siempre esta en VPC Firewall: regla sin el tag `ghostplc-sensor`, zona/proyecto equivocado o puerto no incluido.

## Paso 7: instalar collector, SQLite, API y timers

```bash
cd ~/ghostplc-sensor
python3 -m venv .venv
. .venv/bin/activate
pip install -r collector/requirements.txt
```

Antes de instalar systemd, ejecuta los tests del sensor:

```bash
python -m unittest discover -s tests -v
```

Estos tests simulan logs reales de `docker logs` de Conpot y Cowrie, comprueban que el collector clasifica Modbus, S7, SNMP y SSH, ignora IPs privadas, deduplica eventos repetidos, escribe en SQLite y sirve `/events.json` con bearer token.

Instala systemd con el usuario actual:

```bash
chmod +x scripts/install-systemd.sh
sudo ./scripts/install-systemd.sh
```

El script renderiza las unidades con:

```text
User=$USER real de la VM
WorkingDirectory=/home/TU_USUARIO/ghostplc-sensor
EnvironmentFile=/home/TU_USUARIO/ghostplc-sensor/.env
```

El collector escribe en:

```text
~/ghostplc-sensor/data/ghostplc.sqlite3
```

`events.json` ya no es necesario como almacenamiento. Si quieres exportarlo para debug, pon esto en `.env`:

```text
GHOSTPLC_EXPORT_EVENTS_JSON=1
```

## Paso 8: probar datos

Fuerza una pasada del collector:

```bash
cd ~/ghostplc-sensor
. .venv/bin/activate
python collector/collector.py
sqlite3 data/ghostplc.sqlite3 "select ts,country,protocol,port,event_type from events order by id desc limit 10;"
```

Prueba API:

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/health
curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/events.json
curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/analysis
curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/analysis.txt
```

Desde tu PC:

```powershell
curl.exe -H "Authorization: Bearer TU_TOKEN" http://TU_IP_GCP:8088/events.json
curl.exe -H "Authorization: Bearer TU_TOKEN" http://TU_IP_GCP:8088/analysis
curl.exe -H "Authorization: Bearer TU_TOKEN" http://TU_IP_GCP:8088/analysis.txt
```

Logs utiles:

```bash
sudo systemctl status ghostplc-api.service
sudo systemctl list-timers ghostplc-collector.timer ghostplc-analyzer.timer
sudo journalctl -u ghostplc-collector.service -n 80 --no-pager
sudo journalctl -u ghostplc-analyzer.service -n 80 --no-pager
docker logs --since 5m ghostplc-conpot
docker logs --since 5m ghostplc-cowrie
```

Prueba de humo local completa:

```bash
cd ~/ghostplc-sensor
chmod +x scripts/smoke-test-local.sh
./scripts/smoke-test-local.sh
```

Esta prueba confirma Docker, puertos locales y API. No sustituye las pruebas externas desde tu PC, porque el firewall de Google Cloud solo se valida desde fuera de la VM.

## Paso 9: activar analisis narrativo con OpenAI, opcional

Esto no es obligatorio para el MVP. Es util si quieres que el dashboard vaya contando cosas interesantes: picos por protocolo, paises dominantes, cambios de patron, protocolos nuevos, silencios raros y presion OT frente a ruido SSH.

`gpt-5-nano` encaja bien aqui porque OpenAI lo posiciona para tareas de alto volumen, resumen, clasificacion y coste bajo. El script solo manda eventos compactos: pais, protocolo, puerto, tipo de evento, severidad y timestamps. No envia IPs reales ni hashes de IP al LLM.

El analyzer compara dos ventanas: la ventana actual y la ventana anterior del mismo tamano. Primero calcula senales locales deterministas y luego, si activas OpenAI, pide una bitacora narrativa. La salida del LLM no es JSON; el JSON solo se usa internamente como datos de entrada.

La llamada usa `reasoning.effort=minimal` para mantener latencia y coste bajos. La documentacion de Responses API permite configurar `reasoning.effort` en modelos GPT-5 y derivados.

El analyzer se ejecuta cada hora con `ghostplc-analyzer.timer`. Por defecto analiza los ultimos 60 minutos (`GHOSTPLC_AI_WINDOW_MINUTES=60`), asi que cada texto corresponde a una ventana horaria.

Prompt principal:

```text
Eres GhostPLC, un operador defensivo vigilando honeypots OT/ICS.
Escribes texto normal en espanol: 1, 2 o 3 parrafos cortos.
Tienes tono de operador SOC/industrial: directo, visual, con un punto de consola, pero profesional.
Tu trabajo es contar que esta pasando y detectar tendencias reales: picos contra la ventana anterior,
protocolos nuevos, concentracion por pais, cambios de ritmo, silencio sospechoso y superficie OT.
No devuelvas JSON, YAML, Markdown, tablas, listas, bullets, codigo ni etiquetas tipo [radar].
No uses frases genericas tipo 'observaciones clave', 'en resumen' o 'es importante destacar'.
No inventes malware, actores, CVEs, atribuciones ni paises.
No sugieras campanas, coordinacion, atribucion o intencionalidad salvo que los datos lo sostengan claramente.
No des instrucciones ofensivas.
Si hay pocos datos o son flojos, dilo claro y sin drama.
```

En la VM, edita `~/ghostplc-sensor/.env`:

```text
OPENAI_API_KEY=your_openai_api_key
GHOSTPLC_AI_ENABLED=1
GHOSTPLC_AI_MODEL=gpt-5-nano
GHOSTPLC_AI_REASONING_EFFORT=minimal
GHOSTPLC_AI_WINDOW_MINUTES=60
GHOSTPLC_AI_EVENT_LIMIT=1000
GHOSTPLC_AI_SAMPLE_EVENT_LIMIT=120
```

Reinicia el timer o fuerza una ejecucion:

```bash
sudo systemctl restart ghostplc-analyzer.timer
sudo systemctl start ghostplc-analyzer.service
curl -H "Authorization: Bearer $TOKEN" http://localhost:8088/analysis
```

Si no pones `OPENAI_API_KEY` o dejas `GHOSTPLC_AI_ENABLED=0`, el analizador usa un resumen local basico y no llama a OpenAI.

## Paso 10: preparar dashboard local

En tu PC:

```powershell
cd C:\GhostPLC\ghostplc-dashboard
copy .env.example .env.local
```

Edita `.env.local`:

```text
SENSOR_EVENTS_URL=http://TU_IP_GCP:8088/events.json
SENSOR_ANALYSIS_URL=http://TU_IP_GCP:8088/analysis
SENSOR_API_TOKEN=TU_TOKEN
SENSOR_FETCH_TIMEOUT_MS=6000
```

Arranca:

```powershell
npm run dev
```

Abre:

```text
http://localhost:3000
```

## Paso 11: desplegar en Vercel

Sube `ghostplc-dashboard` a GitHub. No subas `.env.local`.

```powershell
cd C:\GhostPLC\ghostplc-dashboard
git status
git add .
git commit -m "Initial GhostPLC Atlas dashboard"
git branch -M main
git remote add origin TU_REPO_GITHUB
git push -u origin main
```

En Vercel configura variables:

```text
SENSOR_EVENTS_URL=http://TU_IP_GCP:8088/events.json
SENSOR_ANALYSIS_URL=http://TU_IP_GCP:8088/analysis
SENSOR_API_TOKEN=TU_TOKEN
```

Despliega:

```powershell
npm install -g vercel
vercel
vercel --prod
```

## Iteracion: capturar SSH en el puerto 22

Para el MVP deja SSH real en `22` y Cowrie en `2222`.

Esto es deliberado: evita bloquearte fuera de la VM durante el montaje. El coste es que Cowrie capturara menos ruido, porque muchos bots solo prueban SSH en `22`.

Para capturar el ruido SSH real de internet, el orden seguro es:

1. En Google Cloud VPC Firewall, deja `50022/tcp` abierto solo a tu IP.
2. En la VM, edita SSH para escuchar tambien en `50022`.

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
echo "Port 22" | sudo tee /etc/ssh/sshd_config.d/ghostplc-admin-port.conf
echo "Port 50022" | sudo tee -a /etc/ssh/sshd_config.d/ghostplc-admin-port.conf
sudo sshd -t
sudo systemctl reload ssh
```

3. Abre una segunda terminal y verifica que puedes entrar por el puerto alto:

```bash
ssh -p 50022 TU_USUARIO@TU_IP_GCP
```

4. Solo despues, redirige `22 -> 2222` a Cowrie:

```bash
cd ~/ghostplc-sensor
chmod +x scripts/enable-cowrie-port22-redirect.sh
sudo GHOSTPLC_ENABLE_PORT22_REDIRECT=yes ./scripts/enable-cowrie-port22-redirect.sh
```

5. Desde ese momento, administra por:

```bash
ssh -p 50022 TU_USUARIO@TU_IP_GCP
```

No cierres tu sesion SSH original hasta confirmar que el puerto `50022` funciona.

## Para que el sensor atraiga trafico real

No hay que atacar a nadie ni anunciar la IP. Basta con dejar la VM publica y estable:

```text
80/tcp      Conpot HTTP: lo encuentran escaneres web/ICS.
102/tcp     S7: superficie industrial atractiva.
502/tcp     Modbus: muy escaneado en internet.
161/udp     SNMP: ruido constante, aunque UDP puede tardar mas en verse.
2222/tcp    Cowrie MVP: util para pruebas y algunos bots.
22/tcp      fase 2: redirigido a 2222 para capturar el ruido SSH grande.
```

Condiciones importantes:

1. Usa IP estatica.
2. Deja las reglas de VPC Firewall aplicadas con el network tag correcto.
3. Verifica desde fuera de la VM, no solo con `localhost`.
4. Espera horas o dias; los escaneos llegan por ciclos.
5. Para Cowrie serio, haz la fase `50022` + `22 -> 2222`.

## Iteracion: GeoIP real

El collector ya admite MaxMind:

1. Descarga `GeoLite2-City.mmdb` desde MaxMind.
2. Copialo a `~/ghostplc-sensor/GeoLite2-City.mmdb`.
3. Anade en `.env`:

```text
GHOSTPLC_GEOIP_DB=/home/TU_USUARIO/ghostplc-sensor/GeoLite2-City.mmdb
```

4. Fuerza una ejecucion:

```bash
sudo systemctl start ghostplc-collector.service
```

## Checklist final

```text
1. Crear VM Google Cloud e2-medium o e2-standard-2.
2. Asignar IP publica, idealmente estatica.
3. Asignar network tag ghostplc-sensor.
4. Crear reglas VPC Firewall para admin y honeypots.
5. Instalar Docker, Python, SQLite.
6. Subir ghostplc-sensor.
7. Configurar .env y token.
8. Levantar Docker Compose.
9. Instalar venv y requirements.
10. Ejecutar python -m unittest discover -s tests -v.
11. Ejecutar scripts/install-systemd.sh.
12. Ejecutar scripts/smoke-test-local.sh en la VM.
13. Probar /events.json y /analysis con bearer token desde tu PC.
14. Configurar .env.local del dashboard con TU_IP_GCP.
15. Desplegar dashboard en Vercel.
16. Opcional: activar OpenAI gpt-5-nano.
17. Opcional: mover SSH real a 50022 y redirigir 22 a Cowrie.
```

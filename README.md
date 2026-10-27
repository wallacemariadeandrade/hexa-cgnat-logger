# hexa-cgnat-logger
Coletor de logs de CGNAT via Netflow com interface gráfica para pesquisa

Instalação:
```
apt update && apt install git -y
cd /var/opt
git clone https://github.com/wallacemariadeandrade/hexa-cgnat-logger.git
cd hexa-cgnat-logger
chmod +x install.sh
./install.sh
# vai aparecer active no final da execução, se der certo 
``` 
Acesse `http://IP-DO-HOST:8080`
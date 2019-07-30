RSA="\033[31m"
YSA="\033[1;93m"
CEA="\033[0m"
WHS="\033[0;97m"

WHO="$( whoami )"

if [[ "$WHO" != "root" ]]
then
    echo -e ""$RSA"[-]"$WHS" [Errno 1] Failed to copy files: Operation not permitted"$CEA""
    exit
exit
fi

if [[ -d ~/entypreter ]]
then
sleep 0
else
cd ~
{
git clone https://github.com/entynetproject/entypreter.git
} &> /dev/null
cd  ~/entypreter
fi

{
cd 
cd entypreter
cp bin/entypreter /usr/local/bin
chmod +x /usr/local/bin/entypreter
cp bin/entypreter /bin
chmod +x /bin/entypreter
pip3 install -r requirements.txt
} &> /dev/null

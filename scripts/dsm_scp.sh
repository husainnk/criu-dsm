


if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    echo "Usage:"
    echo "$0 <exec name> <host>"
    exit 0
fi


app=$1 
host=$2

cd ~/${app}

time ~/print_ip.sh ${app} ${app} ;
time sudo python3 /users/nkhusain/TransProc_c/criu-3.15/crit/crit  recode . ./aarch64/ aarch64 ${app} ./bin/ y 
ssh ${host} -C "rm -r ~/aarch64; sudo killall -9 ${app}" ;  
scp -r ./aarch64 ${host}:


if [ -z "${3}" ];
then
	exit
fi
echo "========Transfer to  3rd Node====="
ssh $3 -C "rm -r ~/aarch64/*.img; sudo killall -9 dsm_write; mkdir ~/aarch64/" ; 
scp  -r *.img ${3}:~/aarch64/

ssh $4 -C "rm -r ~/aarch64/*.img; sudo killall -9 dsm_write; mkdir ~/aarch64/" ; 
scp  -r *.img ${4}:~/aarch64/


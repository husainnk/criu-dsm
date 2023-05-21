



start_dump(){

	sleep 2;
	echo start  > /tmp/pipe

}

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    echo "Usage:"
    echo "$0 <exec name>"
    exit 0
fi


app=$1 

start_dump &
sudo killall -9 $app  ; sudo rm -r *.img ; sudo ./$app  

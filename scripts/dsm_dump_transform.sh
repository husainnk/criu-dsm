

do_scp(){
	SCP=1 ;
	cat /tmp/pipe_scp ;
	 ~/criu-dsm/scripts/dsm_scp.sh $1 $2 ;
}

if [ "$#" -ne 2 ]; then
  echo "Invalid number of arguments. Expected $0 <app name> <client host name>"
  exit 1
fi

app=$1
client=$2 

do_scp $app $client &

sudo ~/criu-dsm/tools/tracer `pidof ${app}` ; 
sudo ~/criu-dsm/criu-3.15/criu/criu  dump -t `pidof $app` --images-dir  ~/${app} --shell-job -v 


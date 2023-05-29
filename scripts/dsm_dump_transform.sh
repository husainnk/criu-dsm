


app=$1
#sudo kill -SIGSTOP `pidof $app`
sudo ~/criu-dsm/tools/tracer `pidof ${app}` ; 
sudo ~/criu-dsm/criu-3.15/criu/criu  dump -t `pidof $app` --images-dir  ~/${app} --shell-job -v 

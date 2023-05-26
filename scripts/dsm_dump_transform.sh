


app=$1
#sudo kill -SIGSTOP `pidof $app`
sudo /users/nkhusain/TransProc/tools/tracer `pidof ${app}` ; 
sudo /users/nkhusain/tmp/cross-isa/criu-3.15/criu/criu  dump -t `pidof $app` --images-dir  ~/${app} --shell-job -v 

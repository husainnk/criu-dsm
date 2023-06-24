
do_start_dsm_client(){
	sudo killall -9 dsm_client
	sudo ~/criu-dsm/criu-3.15/dsm_client/dsm_client listen 1 2>&1 > /dev/null
}

while [ 1 ] ;
do
       node_id=$1
       app=`cat /tmp/cmd` ;
       do_start_dsm_client &

       echo "Restoring application '$app' at remote_node $node_id"

       cd ~/$app;
       rm  -r *.img ;
       cp ../aarch64/*.img . ;

       python3 ~/criu-dsm/scripts/thread_filter.py $node_id ;
       sudo ~/criu-dsm/criu-3.15/criu/criu  restore -vvv --shell-job;
done

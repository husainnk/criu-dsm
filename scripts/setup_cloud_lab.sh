
if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
    echo "Usage:"
    echo "$0 <host>"
    exit 0
fi

CHOST=$1


if [ "$2" == "--setup-kernel" ] ;  then
	ssh -o StrictHostKeyChecking=no ${CHOST}  -C "sudo dpkg -i /proj/popcornlinux-PG0/mohamed/kernel_images_wp/x86_images/*.deb"
	ssh -o StrictHostKeyChecking=no ${CHOST}  -C "sudo rm -rv /boot/*5.4.0-100*"
	ssh -o StrictHostKeyChecking=no ${CHOST}  -C "sudo ln -sf /boot/initrd.img-5.14.0-custom /boot/initrd.img"
	ssh -o StrictHostKeyChecking=no ${CHOST}  -C "sudo ln -sf /boot/vmlinuz-5.14.0-custom /boot/vmlinuz"
	ssh -o StrictHostKeyChecking=no ${CHOST}  -C "sudo update-grub"
	echo ""
	echo "Setup done: Reboot the device"
	exit;
fi


BRANCH=$2
scp -o  StrictHostKeyChecking=no ./oh_my_zsh_install.sh ${CHOST}:
ssh -o StrictHostKeyChecking=no ${CHOST}  'bash -s'  <<EOT


	$(declare -p  BRANCH)
	echo "Branch $BRANCH"

	yes '' | ssh-keygen -N '' > /dev/null
	sudo apt update
	sudo apt install -y zsh libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler python-protobuf \
	pkg-config libnl-3-dev libnet-dev libcap-dev libbsd-dev python3-pip cmake make libncurses-dev git g++ python3 flex  bison bc  build-essential cmake   libedit-dev python zlib1g-dev rsync wget libelf-dev libssl-dev dwarves
	sudo apt install -y libprotobuf-dev libprotobuf-c-dev protobuf-c-compiler protobuf-compiler python3-protobuf libbsd-dev libcap-dev libnet1-dev libnl-3-dev pkg-config
	python3 -m pip install pyelftools jsonpath-ng pyro4 psutil scp protobuf==3.20 capstone keystone keystone-engine  ip-address

	git clone https://github.com/husainnk/thread_migrater.git
	git clone https://github.com/husainnk/criu-dsm.git -b $BRANCH
	make -C criu-dsm/criu-3.15/  -j8
	if [ "$BRANCH" == "dsm_client" ] ; then
		make -C criu-dsm/criu-3.15/dsm_client
	fi

	chmod +x ./oh_my_zsh_install.sh ; ./oh_my_zsh_install.sh
	git clone https://github.com/zsh-users/zsh-autosuggestions ~/.zsh/zsh-autosuggestions
	echo "source ~/.zsh/zsh-autosuggestions/zsh-autosuggestions.zsh"   >> ~/.zshrc
	echo 'export PS1="%(?:%{%}%{%}%n@%{%}%m ➜ :%{%}➜ ) %{%}%d%{%}[cloud-lab] "'   >> ~/.zshrc

#	### setup kernel
#	sudo dpkg -i /proj/popcornlinux-PG0/mohamed/kernel_images_wp/x86_images/*.deb
#	sudo rm -rv /boot/*5.4.0-100*
#	sudo ln -sf /boot/initrd.img-5.14.0-custom /boot/initrd.img
#	sudo ln -sf /boot/vmlinuz-5.14.0-custom /boot/vmlinuz
#	sudo update-grub

	echo "set hlsearch" >> ~/.vimrc
	echo "set number" >> ~/.vimrc
	echo "set noincsearch" >> ~/.vimrc

	sync

EOT

exit



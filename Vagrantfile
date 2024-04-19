# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/bullseye64"

  config.vm.synced_folder ".", "/vagrant", disabled: true

   config.vm.provider "virtualbox" do |vb|
     vb.gui = false
     vb.memory = "2048"
   end

  config.vm.provision "file", source: "ping", destination: "~/ping"

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y build-essential tcpdump inetutils-ping valgrind
  SHELL

  config.vm.provision "shell", privileged: false, inline: <<-SHELL
    make -C ~/ping fclean
  SHELL
end

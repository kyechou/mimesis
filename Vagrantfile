# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.
Vagrant.configure("2") do |config|
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.
  # https://developer.hashicorp.com/vagrant/docs/vagrantfile/machine_settings

  # You can search for boxes at https://vagrantcloud.com/search.
  config.vm.box = "archlinux/archlinux"
  config.vm.box_check_update = true
  config.vm.disk :disk, size: "128GB", primary: true
  config.vm.hostname = "mimesis"

  # Provider-specific configuration
  # https://developer.hashicorp.com/vagrant/docs/providers/virtualbox/configuration
  config.vm.provider "virtualbox" do |vb|
    vb.gui = false # headless
    vb.name = "mimesis"
    vb.memory = "32768" # MiB
    # https://www.virtualbox.org/manual/ch08.html#vboxmanage-modifyvm
    vb.customize ["modifyvm", :id,
                  "--cpus", "16",
                  "--hwvirtex", "on",
                  "--paravirt-provider", "kvm",
                  "--nested-paging", "on",
                  "--nested-hw-virt", "on",
                  "--large-pages", "on",
                  "--vtx-vpid", "on",
                  "--firmware", "efi64",
                  "--vm-process-priority", "high",
                  "--graphicscontroller", "vmsvga",
                  "--vrde", "off", # disable vbox remote desktop extension
                  "--audio-enabled", "off",
    ]
  end

  # Disable directory sharing. We want to have a separate copy in the VM.
  config.vm.synced_folder ".", "/vagrant", disabled: true

  # Enable provisioning with a shell script. Additional provisioners such as
  # Ansible, Chef, Docker, Puppet and Salt are also available. Please see the
  # documentation for more information about their specific syntax and use.
  # https://developer.hashicorp.com/vagrant/docs/provisioning
  config.vm.provision "shell", privileged: false, reboot: true, inline: <<-SCRIPT
    sudo pacman -Syu --noconfirm git
    git clone https://github.com/kyechou/mimesis.git "$HOME/mimesis"
    cd "$HOME/mimesis"
    ./depends/setup.sh
  SCRIPT
end

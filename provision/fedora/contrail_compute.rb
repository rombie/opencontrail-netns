#!/usr/bin/env ruby

# sudo yum -y install ruby
# sudo ruby < <(curl -s https://raw.githubusercontent.com/rombie/opencontrail-netns/master/provision/fedora/contrail_compute.rb)

# Use this script to install and provision contrail-compute nodes

require 'socket'
require 'ipaddr'
require 'pp'

@ws="#{ENV['HOME']}/contrail"
@intf = "eth1"

def sh(cmd, ignore_exit_code = false)
    puts cmd
    r = `#{cmd}`.chomp
    puts r
    exit -1 if !ignore_exit_code and $?.to_i != 0
    return r
end

def error(msg); puts msg; exit -1 end

# Update ssh configuration
def ssh_setup
    sh("mkdir -p #{ENV['HOME']}/.ssh")
    File.open("#{ENV["HOME"]}/.ssh/config", "a") { |fp|
        conf=<<EOF
UserKnownHostsFile=/dev/null
StrictHostKeyChecking=no
LogLevel=QUIET
EOF
        fp.puts(conf)
    }
    sh("chmod 600 #{ENV['HOME']}/.ssh/config")
end

# Do initial setup
def initial_setup
    ssh_setup
    @contrail_controller = IPSocket.getaddress("contrail-controller")
    error "Cannot resolve contrail-controller host" if @contrail_controller.empty?
    sh("rm -rf #{@ws}")
    sh("mkdir -p #{@ws}")
    Dir.chdir("#{@ws}")
end

# Download and extract contrail and thirdparty rpms
def download_contrail_software
    sh("wget -qO - https://github.com/rombie/opencontrail-netns/blob/master/provision/fedora/contrail-rpms.tar.xz?raw=true | tar Jx")
    sh("wget -qO - https://github.com/rombie/opencontrail-netns/blob/master/provision/fedora/thirdparty.tar.xz?raw=true | tar Jx")
end

# Install third-party software
def install_thirdparty_software_compute
    third_party_rpms = [
    "#{@ws}/thirdparty/xmltodict-0.7.0-0contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/consistent_hash-1.0-0contrail0.el7.noarch.rpm",
    "#{@ws}/thirdparty/python-pycassa-1.10.0-0contrail.el7.noarch.rpm ",
    ]

    sh("yum -y install #{third_party_rpms.join(" ")}")
    sh("yum -y install createrepo docker vim git")
end

# Install third-party software from /cs-shared/builder/cache/centoslinux70/juno
def install_thirdparty_software_controller
    sh("yum -y remove java-1.8.0-openjdk java-1.8.0-openjdk-headless")
 
    sh("yum -y install createrepo vim git vim zsh strace tcpdump")
    sh("yum -y install supervisor supervisord python-supervisor rabbitmq-server python-kazoo python-ncclient")

    third_party_rpms = [
    "#{@ws}/thirdparty/authbind-2.1.1-0.x86_64.rpm",
    "#{@ws}/thirdparty/librdkafka1-0.8.5-2.0contrail0.el7.centos.x86_64.rpm",
    "#{@ws}/thirdparty/librdkafka-devel-0.8.5-2.0contrail0.el7.centos.x86_64.rpm",
    "#{@ws}/thirdparty/cassandra12-1.2.11-1.noarch.rpm",
    "#{@ws}/thirdparty/kafka-2.9.2-0.8.2.0.0contrail0.el7.x86_64.rpm",
    "#{@ws}/thirdparty/python-pycassa-1.10.0-0contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/thrift-0.9.1-12.el7.x86_64.rpm",
    "#{@ws}/thirdparty/python-thrift-0.9.1-12.el7.x86_64.rpm",
    "#{@ws}/thirdparty/python-bitarray-0.8.0-0contrail.el7.x86_64.rpm",
    "#{@ws}/thirdparty/python-jsonpickle-0.3.1-2.1.el7.noarch.rpm",
    "#{@ws}/thirdparty/xmltodict-0.7.0-0contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/python-amqp-1.4.5-1.el7.noarch.rpm",
    "#{@ws}/thirdparty/python-geventhttpclient-1.0a-0contrail.el7.x86_64.rpm",
    "#{@ws}/thirdparty/consistent_hash-1.0-0contrail0.el7.noarch.rpm",
    "#{@ws}/thirdparty/python-kafka-python-0.9.2-0contrail0.el7.noarch.rpm",
    "#{@ws}/thirdparty/redis-py-0.1-2contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/ifmap-server-0.3.2-2contrail.el7.noarch.rpm",
    "#{@ws}/thirdparty/hc-httpcore-4.1-1.jpp6.noarch.rpm",
    "#{@ws}/thirdparty/zookeeper-3.4.3-1.el6.noarch.rpm",
    "#{@ws}/thirdparty/bigtop-utils-0.6.0+243-1.cdh4.7.0.p0.17.el6.noarch.rpm",
    "#{@ws}/thirdparty/python-keystone-2014.1.3-2.el7ost.noarch.rpm",
    "#{@ws}/thirdparty/python-psutil-1.2.1-1.el7.x86_64.rpm",
    "#{@ws}/thirdparty/java-1.7.0-openjdk-1.7.0.55-2.4.7.2.el7_0.x86_64.rpm",
    "#{@ws}/thirdparty/java-1.7.0-openjdk-headless-1.7.0.55-2.4.7.2.el7_0.x86_64.rpm",
    "#{@ws}/thirdparty/log4j-1.2.17-15.el7.noarch.rpm",

    # "#{@ws}/thirdparty/python-psutil-0.6.1-3.el7.x86_64.rpm",
    # "#{@ws}/thirdparty/python-keystone-2014.2.1-1.el7.centos.noarch.rpm",
    ]
    sh("yum -y install #{third_party_rpms.join(" ")}")
end

# Install contrail controller software
def install_contrail_software_controller
    contrail_rpms = [
    "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-database-3.0-4100.fc21.noarch.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/python-contrail-3.0-4100.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-config-3.0-4100.fc21.noarch.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-lib-3.0-4100.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-control-3.0-4100.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-analytics-3.0-4100.fc21.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-web-controller-3.0-4100.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-web-core-3.0-4100.x86_64.rpm",
    "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-setup-3.0-4100.fc21.noarch.rpm",
    "#{@ws}/controller/build/package-build/RPMS/x86_64/contrail-nodemgr-3.0-4100.fc21.x86_64.rpm",
    "#{@ws}/controller/build/package-build/RPMS/x86_64/contrail-utils-3.0-4100.fc21.x86_64.rpm",
    "#{@ws}/controller/build/package-build/RPMS/x86_64/contrail-dns-3.0-4100.fc21.x86_64.rpm",
    "#{@ws}/controller/build/package-build/RPMS/noarch/contrail-openstack-control-3.0-4100.fc21.noarch.rpm",
    "#{@ws}/controller/build/package-build/RPMS/noarch/contrail-openstack-database-3.0-4100.fc21.noarch.rpm",
    "#{@ws}/controller/build/package-build/RPMS/noarch/contrail-openstack-webui-3.0-4100.fc21.noarch.rpm",
    ]
    sh("yum -y install #{contrail_rpms.join(" ")}")

    sh("rpm2cpio #{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-openstack-database-3.0-4100.fc21.noarch.rpm | cpio -idmv")
    sh("cp etc/rc.d/init.d/zookeeper /etc/rc.d/init.d/")
    sh("rpm2cpio #{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-openstack-config-3.0-4100.fc21.noarch.rpm | cpio -idmv")
    sh("cp etc/rc.d/init.d/rabbitmq-server.initd.supervisord /etc/rc.d/init.d/")
    sh("cp -a etc/contrail/supervisord_support_service_files/ /etc/contrail/")

    sh("rpm2cpio #{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-openstack-control-3.0-4100.fc21.noarch.rpm | cpio -idmv")
    sh("cp -a etc/contrail/supervisord_support_service_files/ /etc/contrail/")
    sh("cp -a etc/contrail/supervisord_control_files/ /etc/contrail/")
    sh("cp etc/contrail/supervisord_config_files/* /etc/contrail/supervisord_config_files/")

    sh("service zookeeper start")
    sh("service rabbitmq-server start")
    sh("service supervisor-database start")
    sh("service supervisor-control start")
    sh("service supervisor-config start")
    sh("service supervisor-analytics start")

    sh("netstat -anp | \grep LISTEN | \grep 5672") # RabbitMQ
    sh("netstat -anp | \grep LISTEN | \grep 2181") # ZooKeeper
    sh("netstat -anp | \grep LISTEN | \grep -w 9160") # Cassandra
    sh("netstat -anp | \grep LISTEN | \grep -w 8083") # Control-Node
    sh("netstat -anp | \grep LISTEN | \grep -w 5998") # discovery
    sh("netstat -anp | \grep LISTEN | \grep 8443") # IFMAP-Server
    sh("netstat -anp | \grep LISTEN | \grep -w 8082") # API-Server
    sh("netstat -anp | \grep LISTEN | \grep -w 8086") # Collector
    sh("netstat -anp | \grep LISTEN | \grep -w 8081") # OpServer
end

# Provision contrail-controller
def provision_contrail_controller
    sh(%{sed -i 's/Xss180k/Xss280k/' /etc/cassandra/conf/cassandra-env.sh})
    sh(%{echo "api-server:api-server" >> /etc/ifmap-server/basicauthusers.properties})
    sh(%{echo "schema-transformer:schema-transformer" >> /etc/ifmap-server/basicauthusers.properties})
    sh(%{echo "svc-monitor:svc-monitor" >> /etc/ifmap-server/basicauthusers.properties})
    sh(%{echo "control-user:control-user-passwd" >> /etc/ifmap-server/basicauthusers.properties})
    sh(%{sed -i 's/911%(process_num)01d/5998/' /etc/contrail/supervisord_config_files/contrail-discovery.ini})
    sh(%{sed -i 's/91%(process_num)02d/8082/' /etc/contrail/supervisord_config_files/contrail-api.ini})
    sh(%{sed -i 's/# port=5998/port=5998/' /etc/contrail/contrail-control.conf})
    sh(%{sed -i 's/# server=127.0.0.1/server=127.0.0.1/' /etc/contrail/contrail-control.conf})
    sh(%{sed -i 's/# port=5998/port=5998/' /etc/contrail/contrail-collector.conf})
    sh(%{sed -i 's/# server=0.0.0.0/server=127.0.0.1/' /etc/contrail/contrail-collector.conf})
    sh(%{sed -i 's/# user=control-user/user=control-user/g' /etc/contrail/contrail-control.conf})
    sh(%{sed -i 's/# password=control-user-passwd/password=control-user-passwd/' /etc/contrail/contrail-control.conf})
    sh(%{python /opt/contrail/utils/provision_control.py --api_server_ip 10.245.1.2 --api_server_port 8082 --router_asn 64512 --host_name contrail-controller --host_ip 10.245.1.2 --oper add})
end

# Install contrail compute software
def install_contrail_software_compute
    contrail_rpms = [
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/python-contrail-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/python-contrail-vrouter-api-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-utils-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-init-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-lib-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-agent-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-setup-3.0-4100.fc21.noarch.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-vrouter-common-3.0-4100.fc21.noarch.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-vrouter-init-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-utils-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/x86_64/contrail-nodemgr-3.0-4100.fc21.x86_64.rpm",
        "#{@ws}/contrail/controller/build/package-build/RPMS/noarch/contrail-vrouter-common-3.0-4100.fc21.noarch.rpm",
    ]
    sh("yum -y install #{contrail_rpms.join(" ")}")
end

# Provision contrail-vrouter agent and vrouter kernel module
def provision_contrail_compute
    prefix = sh("ip addr show dev eth1|\grep -w inet | \grep -v dynamic | awk '{print $2}'")
    error("Cannot retrieve #{@intf}'s IP address") if prefix !~ /(.*)\/(\d+)$/
    ip = $1
    msk = IPAddr.new(prefix).inspect.split("/")[1].chomp.chomp(">")        
    gw = sh(%{netstat -rn |\grep "^0.0.0.0" | awk '{print $2}'})

    ifcfg = <<EOF
#Contrail vhost0
DEVICE=vhost0
ONBOOT=yes
BOOTPROTO=none
IPV6INIT=no
USERCTL=yes
IPADDR=#{ip}
NETMASK=#{msk}
NM_CONTROLLED=no
#NETWORK MANAGER BUG WORKAROUND
SUBCHANNELS=1,2,3
GATEWAY=#{gw}
DNS1=8.8.8.8
#DOMAIN="contrail.juniper.net. juniper.net. jnpr.net. contrail.juniper.net"
EOF
    File.open("/etc/sysconfig/network-scripts/ifcfg-vhost0", "w") { |fp|
        fp.puts(ifcfg)
    }

    sh("sed 's/__DEVICE__/#{@intf}/' /etc/contrail/agent_param.tmpl > /etc/contrail/agent_param")
    sh("sed -i 's/# type=kvm/type=kvm/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("/sbin/ifconfig eth1 |\grep ether | awk '{print $2}' | xargs echo > /etc/contrail/default_pmac")
    sh("sed -i 's/# name=vhost0/name=vhost0/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("sed -i 's/# physical_interface=vnet0/physical_interface=#{@intf}/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("sed -i 's/# server=10.204.217.52/server=#{@contrail_controller}/' /etc/contrail/contrail-vrouter-agent.conf")
    sh("sshpass -p vagrant ssh contrail-controller sudo python /opt/contrail/utils/provision_vrouter.py --host_name #{sh('hostname')} --host_ip #{ip} --api_server_ip #{@contrail_controller} --oper add")
    puts("Please do sudo reboot, followed by")
    puts("sudo service supervisor-vrouter restart; sudo service contrail-vrouter-agent restart")
end

def main
    initial_setup
    download_contrail_software
    # install_thirdparty_software_compute
    # install_contrail_software_compute
    # provision_contrail_compute
    install_thirdparty_software_controller
    install_contrail_software_controller
    provision_contrail_controller
end

main

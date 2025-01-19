#!/usr/bin/env bash

set -e


_script_home="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"


_os=""
_release=""
_arch=""

_mem="6144"
_cpu="2"
_nc="e1000"
_sshport="10022"
_useefi=""
_detach=""
_vpath=""

_workingdir="$_script_home/output"

while [ ${#} -gt 0 ]; do
  case "${1}" in
  --os)
    _os="$2"
    shift
    ;;
  --release)
    _release="$2"
    shift
    ;;
  --arch)
    _arch="$2"
    shift
    ;;
  --mem)
    _mem="$2"
    shift
    ;;
  --cpu)
    _cpu="$2"
    shift
    ;;
  --workingdir)
    _workingdir="$2"
    shift
    ;;
  --nc)
    _nc="$2"
    shift
    ;;
  --sshport)
    _sshport="$2"
    shift
    ;;
  --builder)
    _builder="$2"
    shift
    ;;
  --uefi)
    _useefi="1"
    ;;
  --detach | -d)
    _detach="1"
    ;;
  -v)
    _vpath="$2"
    shift
    ;;
  *)
    echo "Unknown parameter: $1"
    exit 1
    ;;
  esac
  shift 1
done


if [ -z "$_os" ]; then
  echo "use parameters:  --os freebsd  [--release 15.0] [--arch aarch64] [--cpu 2] [--mem 6144] [--sshport 10022] [-v /paht/host:/path/vm] [--workingdir /path/to/data]  [--uefi] [--detach | -d]"
  exit 1
fi


if [ "$_os" = "freebsd" ]; then
  _useefi=1
fi

if [ "$_arch" = "x86_64" ] || [ "$_arch" = "amd64" ]; then
  _arch=""
fi
if [ "$_arch" = "arm" ]; then
  _arch="aarch64"
fi



builder="vmactions/${_os}-builder"



working="$_workingdir"



_endswith() {
  _str="$1"
  _sub="$2"
  echo "$_str" | grep -- "$_sub\$" >/dev/null 2>&1
}

check_url_exists() {
  url=$1
  http_status=$(curl -o /dev/null --silent --head --write-out '%{http_code}' "$url")
  if [[ "$http_status" -ge 200 && "$http_status" -lt 400 ]]; then
    return 0
  else
    return 1
  fi
}


mkdir -p "$working/${_os}"


echo "Using arch: $_arch"



if [ "$_builder" ]; then
  echo "Builder version: $_builder"
  if [ -z "$_release" ]; then
    _meta="https://api.github.com/repos/$builder/releases/tags/v$_builder"
    _metafile="$working/${_os}/meta.json"
    curl -L "$_meta" >"$_metafile"
    if [ "$_arch" ]; then
     _release="$(cat "$_metafile"  |  jq -r '.assets[].browser_download_url' | grep ${_arch}.qcow2.zst | sort -r | head -1 | cut -d '/' -f 9 | cut -d - -f 2 )"
    else
     _release="$(cat "$_metafile"  |  jq -r '.assets[].browser_download_url' | grep qcow2.zst | sort -r | head -1 | cut -d '/' -f 9 | cut -d - -f 2 | rev | cut -d . -f 3- | rev)"
    fi
  fi
  if [ "$_arch" ]; then
    zst_link="https://github.com/$builder/releases/download/v$_builder/$_os-${_release}-${_arch}.qcow2.zst"
  else
    zst_link="https://github.com/$builder/releases/download/v$_builder/$_os-${_release}.qcow2.zst"
  fi
fi


allReleases="$working/${_os}/all.json"


if [ -z "$_release" ]; then
  curl -L "https://api.github.com/repos/$builder/releases" >"$allReleases"
  if [ "$_arch" ]; then
    _release="$(cat "$allReleases"  |  jq -r '.[].assets[].browser_download_url' | grep ${_arch}.qcow2.zst | sort -r | head -1 | cut -d '/' -f 9 | cut -d - -f 2 )"
  else
    _release="$(cat "$allReleases"  |  jq -r '.[].assets[].browser_download_url' | grep qcow2.zst | sort -r | head -1 | cut -d '/' -f 9 | cut -d - -f 2 | rev | cut -d . -f 3- | rev)"
  fi
fi

echo "Using release: $_release"
  
  
if [ -z "$zst_link" ]; then
  if [ ! -e "$allReleases" ]; then
    curl -L "https://api.github.com/repos/$builder/releases" >"$allReleases"
  fi
  
  if [ -z "$_arch" ] || [ "$_arch" = "x86_64" ]; then
    zst_link="$(cat "$allReleases"  |  jq -r '.[].assets[].browser_download_url' | grep ${_os}-${_release}.qcow2.zst | sort -r | head -1)"
  else
    zst_link="$(cat "$allReleases"  |  jq -r '.[].assets[].browser_download_url' | grep ${_os}-${_release}-${_arch}.qcow2.zst| sort -r | head -1)"
  fi
fi


echo "Using zst_link: $zst_link"

if [ -z "$zst_link" ]; then
  echo "can not find the zst file link."
  exit 1
fi

if [ -z "$_builder" ]; then
  _builder=$(echo "$zst_link" | cut -d / -f 8 | tr -d v)
  echo "get _builder ver: $_builder"
fi


_output="$working/${_os}/v${_builder}"
mkdir -p "$_output"


ovafile="$(echo "$zst_link" | rev  | cut -d / -f 1 | rev)"
qow2="$(echo "$zst_link" | rev  | cut -d / -f 1 | cut -d . -f 2- | rev)"
 

if [ ! -e "$_output/$qow2" ]; then

  echo "Downloading $zst_link"
  axel -n 8 -o "$_output/$ovafile"  "$zst_link"
  
  for i in $(seq 1 9) ; do
    _url="${zst_link}.$i"
    echo "Checking $_url"
    if ! check_url_exists "$_url"; then
      echo "break"
      break
    fi
    axel -n 8 -o "$_output/${ovafile}.$i"  "$_url"
    ls -lah
    cat "$_output/${ovafile}.$i" >>"$_output/$ovafile"
    rm -f "$_output/${ovafile}.$i"
  done

  echo "Download finished, extracting"
  if _endswith "$zst_link" ".xz"; then
    #just to keep compatible with the old xz editions
    xz -v -d -c "$_output/$ovafile" >"$_output/$qow2"
  else
    zstd -d "$_output/$ovafile" -o "$_output/$qow2"
    rm -f "$_output/$ovafile"
  fi
  echo "Extract finished"
fi


###############################################
_hostid_link="$(echo "$zst_link" | sed "s/.qcow2.zst/-host.id_rsa/")"
echo "Host id link: $_hostid_link"
_hostid="$_output/$(echo "$_hostid_link" | rev | cut -d / -f 1 | rev)"
echo "Host id file: $_hostid"

if [ ! -e "$_hostid" ]; then
 curl -L  "$_hostid_link" >"$_hostid"
 chmod 600 "$_hostid"
fi


_vmpub_link="$(echo "$zst_link" | sed "s/.qcow2.zst/-id_rsa.pub/")"
echo "VM pub key link: $_vmpub_link"
_vmpub="$_output/$(echo "$_vmpub_link" | rev | cut -d / -f 1 | rev)"
if [ ! -e "$_vmpub" ]; then
  echo "VM pub key file: $_vmpub"
  curl -L  "$_vmpub_link" >"$_vmpub"
fi



ls -lah "$_output"

##############################################




_name="$_os-$_release"
if [ "$_arch" ]; then
  _name="$_os-$_release-$_arch"
fi

_qowfull="$_output/$qow2"

_qemu_args="-monitor telnet:localhost:7100,server,nowait,nodelay  
-device virtio-balloon-pci -display vnc=:0 -serial mon:stdio  
-name $_name,process=$_name     
-smp ${_cpu:-2} 
-m ${_mem:-6144}  
-device ${_nc:-e1000},netdev=hostnet0 
-netdev user,id=hostnet0,net=192.168.122.0/24,dhcpstart=192.168.122.50,hostfwd=tcp::${_sshport:-10022}-:22
-drive file=${_qowfull},format=qcow2,if=virtio "


_current="$(uname -m)"
_qemu_bin="qemu-system-x86_64"

if [ "$_arch" = "aarch64" ]; then
  _qemu_bin="qemu-system-aarch64"
  if [ "$_current" = "aarch64" ]; then
    echo " not implemented"
    exit 1
  else
    #run arm64 on x86
    _efi="$_output/$_name-QEMU_EFI.fd"
    if [ ! -e "$_efi" ]; then
      dd if=/dev/zero of="$_efi" bs=1M count=64
      dd if=/usr/share/qemu-efi-aarch64/QEMU_EFI.fd of="$_efi" conv=notrunc
    fi
    _efivars="$_output/$_name-QEMU_EFI_VARS.fd"
    if [ ! -e "$_efivars" ]; then
      dd if=/dev/zero of="$_efivars" bs=1M count=64
    fi
    
    _qemu_args="$_qemu_args -machine virt,accel=tcg,gic-version=3 
    -cpu cortex-a72 
    -rtc base=utc 
    -drive if=pflash,format=raw,readonly=on,file=${_efi}
    -drive if=pflash,format=raw,file=${_efivars}
    "
    
  fi

else
  if [ "$_current" = "x86_64" ]; then
    #run x86 on x86
    if [ -e "/dev/kvm" ]; then
      _qemu_args="$_qemu_args -machine pc,accel=kvm,hpet=off,smm=off,graphics=off,vmport=off 
    -enable-kvm -global kvm-pit.lost_tick_policy=discard 
    -global kvm-pit.lost_tick_policy=discard 
    -cpu host,kvm=on,l3-cache=on,+hypervisor,migratable=no,+invtsc 
    -rtc base=utc,driftfix=slew "
    else
      _qemu_args="$_qemu_args -machine pc,accel=tcg,hpet=off,smm=off,graphics=off,vmport=off 
    -cpu host,l3-cache=on,+hypervisor,migratable=no,+invtsc 
    -rtc base=utc,driftfix=slew "
    fi
    if [ "$_useefi" ]; then
      _efi="/usr/share/qemu/OVMF.fd"
      _efivars="$_output/$_name-OVMF_VARS.fd"
      if [ ! -e "$_efivars" ]; then
        dd if=/dev/zero of="$_efivars" bs=1M count=4
      fi
      _qemu_args="$_qemu_args -drive if=pflash,format=raw,readonly=on,file=${_efi}
    -drive if=pflash,format=raw,file=${_efivars}
    "
    fi
  else
    echo "not implemented"
    exit 1
  fi
fi


echo "_qemu_bin=$_qemu_bin"
echo "_qemu_args=$_qemu_args"



#########################################

CONSOLE_NAME="$_name-console"
CONSOLE_FILE="$_output/$_name-console.log"
  
  



rm -f "$CONSOLE_FILE"
screen -dmLS "$CONSOLE_NAME" -Logfile "$CONSOLE_FILE" -L $_qemu_bin $_qemu_args

(
#press enter key to speed up booting
for i in $(seq 0 9) ; do
  screen -S "$CONSOLE_NAME" -p 0 -X stuff "\r"
  sleep 1
done
)&


####################################




_initInVM() {
  #initialize file mounting
  _retry=0
  while ! timeout 2 ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$_hostid" -p "${_sshport}" root@localhost exit >/dev/null 2>&1; do
    echo "vm is booting just wait."
    sleep 2
    _retry=$(($_retry + 1))
    if [ $_retry -gt 100 ]; then
      echo "Boot failed."
      return 1
    fi
  done
  echo "Boot ready"

  #init ssh
  mkdir -p ~/.ssh
  chmod 600 ~/.ssh
  sudo ls -lah ~/.ssh/authorized_keys
  sudo cat "$_vmpub" >> ~/.ssh/authorized_keys
  if ! grep "Include config.d" ~/.ssh/config; then
    echo 'Include config.d/*.conf' >>~/.ssh/config
  fi
  chmod 600 ~/.ssh/config
  mkdir -p ~/.ssh/config.d
  echo "

Host $_name
  StrictHostKeyChecking no
  UserKnownHostsFile=/dev/null
  User root
  HostName localhost
  Port $_sshport
  IdentityFile=$_hostid
  
">~/.ssh/config.d/$_name.conf
  echo "======================================"
  echo ""
  echo "You can login the vm with: ssh $_name"
  echo ""
  echo "======================================"
  
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$_hostid" -p "${_sshport}" root@localhost sh <<EOF
echo 'StrictHostKeyChecking=no' >.ssh/config

echo "Host host" >>.ssh/config
echo "     HostName  192.168.122.2" >>.ssh/config
echo "     User $USER" >>.ssh/config
echo "     ServerAliveInterval 1" >>.ssh/config

EOF

  if [ "$_vpath" ]; then
    _vhost="$(echo "$_vpath" | cut -d : -f 1)"
    echo "Mount host dir: $_vhost"
    _vguest="$(echo "$_vpath" | cut -d : -f 2)"
    echo "Mount to guest dir: $_vguest"
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$_hostid" -p "${_sshport}" root@localhost sh <<EOF
mkdir -p "$_vguest"

if [ "$_os" = "netbsd" ]; then
  if ! /usr/sbin/mount_psshfs host:"$_vhost" "$_vguest"; then
    echo "error run sshfs in vm."
   exit 1
  fi
  echo "sshfs OK"
elif sshfs -o reconnect,ServerAliveCountMax=2,allow_other,default_permissions host:$_vhost $_vguest ; then
  echo "run sshfs in vm is OK, show mount:"
  /sbin/mount
  if [ "$_os" = "netbsd" ]; then
    tree $_vhost
  fi
else
  echo "error run sshfs in vm."
  exit 1
fi

EOF

  fi
}





__INTERACTIVE=""
if [ -t 1 ]; then
  __INTERACTIVE="1"
fi


if [ "$__INTERACTIVE" ] && [ -z "$_detach" ]; then
  _initInVM >dev/null &
  screen -r "$CONSOLE_NAME"
else
  _initInVM
  if [ -z "$_detach" ]; then
    screen -r "$CONSOLE_NAME"
  fi
fi






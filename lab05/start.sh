rm -rf dist hellomod qemu.sh
tar -jxvf dist.tbz
tar -jxvf hellomod.tbz
cd dist
mkdir rootfs && cd rootfs && bunzip2 -c ../rootfs.cpio.bz2 | cpio -idv && cd ..
# cd ../kshrammod && make
cd ../hellomod && make
mkdir -p ../dist/rootfs/modules
# cp kshrammod.ko ../dist/rootfs/modules
cp hello hellomod.ko ../dist/rootfs/modules
cd ../dist/rootfs
find . -print0 | cpio --null -ov --format=newc | bzip2 -9 > ../rootfs.cpio.bz2 && cd ..
rm -rf rootfs
cd ..
sh qemu.sh

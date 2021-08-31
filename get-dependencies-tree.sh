#!/bin/sh

ignore_pkgs="pipdeptree,pip-licenses,PTable,graphviz,pip,wheel,setuptools"

cat>get-deps.sh <<EOF
#!/bin/sh

pip install pipdeptree pip-licenses graphviz
apt update && apt install -y graphviz

pipdeptree --graph-output png -e $ignore_pkgs > dependencies-tree.png

pip-licenses -i $(echo $ignore_pkgs | tr ',' ' ') > dependencies-licenses.txt
EOF

chmod +x get-deps.sh

docker build . -t local_test_image

docker run --entrypoint /bin/sh -v $(pwd):/deptree --workdir /deptree local_test_image /deptree/get-deps.sh

rm get-deps.sh

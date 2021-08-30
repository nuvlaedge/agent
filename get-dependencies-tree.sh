#!/bin/sh

cat >get-deps.sh <<EOF
#!/bin/sh

pip install pipdeptree pip-licenses graphviz
apt update && apt install -y graphviz

ignore_pkgs="pipdeptree,pip-licenses,graphviz,pip,wheel,setuptools"

pipdeptree --graph-output png -e $ignore_pkgs > dependencies-tree.png

pip-licenses -i $ignore_pkgs > dependencies-licenses.txt
EOF

chmod +x get-deps.sh

docker build . -t local_test_image

docker run --entrypoint /bin/sh -v ./:/agent --workdir /agent local_test_image /agent/get-dependencies-tree.sh

rm get-deps.sh

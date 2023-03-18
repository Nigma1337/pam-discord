git clone https://github.com/Nigma1337/openssh-portable.git
cd openssh-portable
autoreconf
./configure --with-pam
make install
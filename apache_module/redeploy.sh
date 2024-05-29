
# Compile module:
# 
g++ -std=c++20 -fPIC -c mod_hello.cpp mod_hello.o -I /usr/include/apache2 -I /usr/include/apr-1.0

# Link module into Shared Object library:
#
g++ -shared -fPIC -o mod_hello.so mod_hello.o

# Disable module if it was already enabled (so that we do a clean activate)
#
a2dismod mod_hello

# Install and activate module:
#
apxs2 -ia -n mod_hello mod_hello.so

# Restart Apache so changes take effect:
#
echo "Restarting Apache..."
systemctl restart apache2
echo "Done!"

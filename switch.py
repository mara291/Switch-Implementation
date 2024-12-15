1 2 3

### 1. Learning
Am creat un dictionar mac_table pentru a asocia fiecare MAC cu portul 
pe care a ajuns. La primirea unui pachet, actualizez mac_table si in functie 
de adresa destinatie, trimit un pachet unicast sau broadcast.

### 2. VLAN
Folosesc un dictionar ports, iar din configuratia switch-ului imi notez 
pentru fiecare port VLAN-ul sau daca e Trunk(0). La trimiterea pachetelor, 
adaug/scot headerul 802.1Q dupa caz. Pachetul va ajunge la destinatie doar 
daca ambii hosts fac parte din acelasi VLAN.

### 3. STP
Pentru a memora state-ul unui port folosesc un dictionar port_states. Am 
modificat functia send_bdpu_every_sec pentru a trimite frame-uri BDPU cu 
datele necesare. La fieacare pachet primit in main, verific daca este BDPU, 
si modific root bridge dupa caz. La final, porturile care pot crea bucle sunt 
setate pe Blocking.
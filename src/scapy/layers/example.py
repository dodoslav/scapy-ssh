def fname():
    """example """
    
    target = ('10.10.18.3',22);
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM); 
    s.connect(target); 
    p = SSH()/SSHIdent(ident="SSH-2.0-x\r\n"); 
    p.show(); 
    s.sendall(str(p)); 
    resp = s.recv(1024); # received identification
    SSH(resp).show(); 
    resp = s.recv(1024); 
    SSH(resp).show(); 
    p=SSHMessage()/SSHKexInit( languages_client_to_server="de,uk,de,uk",reserved=0);  # KEXINIT
    p = padding_fix(p); 
    p.show2(); 
    s.sendall(str(p));
     
    p=SSHMessage()/SSHGexRequest(); # client sends SSH_MSG_KEX_DH_GEX_GROUP
    p= padding_fix(p); 
    p.show2(); 
    s.sendall(str(p)); 

    resp = s.recv(1024); # server responds with SSH_MSG_KEX_DH_GEX_GROUP 
    SSH(resp).show();

    res = SSH(resp); 
    p = util.inflate_long(res.p); 
    g = util.inflate_long(res.g); 
    x = generateX(p); 
    e = pow(g,x,p); 
    udl=util.deflate_long(e); 
    asb = asbytes(udl); 
    len_e = struct.pack('>I',len(asb)); 

    p=SSHMessage()/SSHGexInit(len_e=len_e, e=asb); # client responds with SSH_MSG_KEX_DH_GEX_INIT
    p=padding_fix(p); 
    p.show(); 
    s.sendall(str(p)); 

    resp = s.recv(1024); # client responds with SSH_MSG_KEX_DH_GEX_REPLY 
    SSH(resp).show();


# main.py
import os
import base64
#from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
#from cryptography.fernet import Fernet
from flask import Flask, render_template, Response, redirect, request, session, abort, url_for
import mysql.connector
import hashlib
import shutil
from datetime import datetime
from datetime import date
import datetime
import json
import math
import random
from random import randint

from flask_mail import Mail, Message
from flask import send_file
from werkzeug.utils import secure_filename
import urllib.parse
from urllib.request import urlopen
import webbrowser
import socket
#alg
from Crypto import Random
from Crypto.Cipher import AES

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  charset="utf8",
  database="cloud_cloaking"

)
app = Flask(__name__)
##session key
app.secret_key = 'abcdef'

UPLOAD_FOLDER = 'static/upload'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#####
#######
class AESCipher(object):

    def __init__(self, key):
        self.bs = AES.block_size
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]
#############

@app.route('/', methods=['GET', 'POST'])
def index():
    msg=""
    now = datetime.datetime.now()
    rtime=now.strftime("%H:%M")

    #ff=open("mm.mp4","w")
    #ff.write("ggjhfjfhvdfjvn34543$%^*&*cv@#$@vb98623%$^%&^*&hello#$#$DFVDF%2@#@#@656DFDF")
    #ff.close()

    '''ff=open("mm.mp4","r")
    v=ff.read()
    ff.close()
    print(v)'''
    
    return render_template('web/index.html',msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
    msg=""

    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM data_owner WHERE owner_id = %s AND password = %s && status=1', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('upload'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login.html',msg=msg)

@app.route('/login_admin', methods=['GET', 'POST'])
def login_admin():
    msg=""

    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        
        cursor = mydb.cursor()
        cursor.execute('SELECT * FROM admin_login WHERE username=%s && password=%s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('admin'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login_admin.html',msg=msg)

@app.route('/login_user', methods=['GET', 'POST'])
def login_user():
    msg=""

    
    if request.method=='POST':
        uname=request.form['uname']
        pwd=request.form['pass']
        cursor = mydb.cursor()
        lat=request.form['lat']
        lon=request.form['lon']
        loc=lat+"|"+lon
        ff=open("static/geo.txt","w")
        ff.write(loc)
        ff.close()
        cursor.execute('SELECT * FROM data_user WHERE username = %s AND password = %s', (uname, pwd))
        account = cursor.fetchone()
        if account:
            session['username'] = uname
            return redirect(url_for('userhome'))
        else:
            msg = 'Incorrect username/password!'
    return render_template('web/login_user.html',msg=msg)



@app.route('/register', methods=['GET', 'POST'])
def register():
    msg=""
    mycursor = mydb.cursor()
    mycursor.execute("SELECT max(id)+1 FROM data_owner")
    maxid = mycursor.fetchone()[0]

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
            
    if maxid is None:
        maxid=1
    if request.method=='POST':
        name=request.form['name']
        mobile=request.form['mobile']
        email=request.form['email']
        city=request.form['city']
        uname=request.form['uname']
        pass1=request.form['pass']
        cursor = mydb.cursor()

        cursor.execute('SELECT count(*) FROM data_owner WHERE owner_id = %s ', (uname,))
        cnt = cursor.fetchone()[0]
        if cnt==0:
            result = hashlib.md5(uname.encode())
            key=result.hexdigest()
            
            sql = "INSERT INTO data_owner(id,name,mobile,email,city,owner_id,password,reg_date) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid,name,mobile,email,city,uname,pass1,rdate)
            cursor.execute(sql, val)
            mydb.commit()            
            print(cursor.rowcount, "Registered Success")
            msg="success"
        else:
            msg='fail'
    return render_template('web/register.html',msg=msg)

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    msg=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor1 = mydb.cursor()
    cursor1.execute("SELECT * FROM data_owner")
    data=cursor1.fetchall()
    

    if act=="ok":
        did = request.args.get('did')
        cursor1.execute('update data_owner set status=1 where id=%s', (did,))
        mydb.commit()
        msg="ok"

    return render_template('admin.html',msg=msg,act=act,data=data)


def data_block():
    ############
    ff=open("static/key.txt","r")
    k=ff.read()
    ff.close()
    
    bcdata="CID:"+uname+",Time:"+val1+",Unit:"+val2
    dtime=rdate+","+rtime

    bcc=bcdata+"-"+dtime
    benc=obj.encrypt(bcc)
    benc1=benc.decode("utf-8")

    ff1=open("static/js/d1.txt","r")
    bc1=ff1.read()
    ff1.close()
    
    
    if k=="1":
        result = hashlib.md5(bcdata.encode())
        key=result.hexdigest()
        print(key)
        v=k+"-"+key+"-"+benc1

        ff1=open("static/js/d1.txt","w")
        ff1.write(v)
        ff1.close()
        
        dictionary = {
            "ID": "1",
            "Pre-hash": "00000000000000000000000000000000",
            "Hash": key,
            "Date/Time": dtime
        }

        k1=int(k)
        k2=k1+1
        k3=str(k2)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()
        
    else:
        pre_k=""
        k1=int(k)
        k2=k1-1
        k4=str(k2)
        
        g1=bc1.split("|")
        for g2 in g1:
            g3=g2.split("-")
            if k4==g3[0]:
                pre_k=g3[1]
                break

        
        result = hashlib.md5(bcdata.encode())
        key=result.hexdigest()
        

        v="|"+k+"-"+key+"-"+benc1

        k3=str(k2)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

        ff1=open("static/js/d1.txt","a")
        ff1.write(v)
        ff1.close()

        
        
        dictionary = {
            "ID": k,
            "Pre-hash": pre_k,
            "Hash": key,
            "Date-Time": dtime
        }
        k21=int(k)+1
        k3=str(k21)
        ff1=open("static/key.txt","w")
        ff1.write(k3)
        ff1.close()

    m=""
    if k=="1":
        m="w"
    else:
        m="a"
    # Serializing json
    json_object = json.dumps(dictionary, indent=4)
     
    # Writing to sample.json
    with open("static/gridchain.json", m) as outfile:
        outfile.write(json_object)
    ##########

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    msg=""
    act=""
    if 'username' in session:
        uname = session['username']
    print(uname)

    mycursor = mydb.cursor()
    mycursor.execute('SELECT * FROM data_owner where owner_id=%s',(uname, ))
    rr=mycursor.fetchone()
    name=rr[1]
    
    
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    rtime=now.strftime("%H:%M")
    imgext=['py','avi','css','doc','docx','gif','html','jpg','jpeg','mov','mp3','mp4','pdf','png','ppt','pptx','txt','wav','xls','xlsx','csv']
    img=['img_def.jpg','img_avi.jpg','img_css.jpg','img_doc.jpg','img_doc.jpg','img_gif.jpg','img_html.jpg','img_jpg.jpg','img_jpg.jpg','img_mov.jpg','img_mp3.jpg','img_mp4.jpg','img_pdf.jpg','img_png.jpg','img_ppt.jpg','img_ppt.jpg','img_txt.jpg','img_wav.jpg','img_xls.jpg','img_xls.jpg','img_csv.jpg']
    
    if request.method=='POST':
        description=request.form['description']

        mycursor.execute("SELECT max(id)+1 FROM data_files")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        
        file_type = file.content_type
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file:
            fname = "F"+str(maxid)+file.filename
            filename = secure_filename(fname)
            
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            bsize=os.path.getsize("static/upload/"+filename)
            fsize=bsize/1024
            file_size=round(fsize,2)

            ff=filename.split('.')
            i=0
            file_ext=''
            for fimg in imgext:
                if fimg==ff[1]:
                    file_ext=img[i]
                    break
                else:
                    file_ext=img[0]
                i+=1
                    
            rn=randint(1,3)
            fn="d"+str(rn)+".txt"
            ff=open("static/assets/"+fn,"r")
            fd=ff.read()
            ff.close()

            ff1=open("static/data/"+filename,"w")
            ff1.write(fd)
            ff1.close()

            ##store
            sql = "INSERT INTO data_files(id,owner_id,description,file_name,file_type,file_size,reg_date,reg_time,file_extension) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid,uname,description,filename,file_type,file_size,rdate,rtime,file_ext)
            mycursor.execute(sql,val)
            mydb.commit()
            
            msg="success"

    mycursor.execute('SELECT * FROM data_files where owner_id=%s order by id desc limit 0,10',(uname, ))
    data=mycursor.fetchall()
    
    return render_template('upload.html',msg=msg,data=data,name=name)

@app.route('/view_user', methods=['GET', 'POST'])
def view_user():
    msg=""
    act=request.args.get("act")
    if 'username' in session:
        uname = session['username']
    print(uname)

    mycursor = mydb.cursor()
    mycursor.execute('SELECT * FROM data_owner where owner_id=%s',(uname, ))
    rr=mycursor.fetchone()
    name=rr[1]

    mycursor.execute('SELECT * FROM data_user where owner_id=%s',(uname, ))
    data=mycursor.fetchall()

    if act=="del":
        did = request.args.get('did')
        cursor1.execute('delete from data_user where id=%s', (did,))
        mydb.commit()
        msg="ok"
    
    return render_template('view_user.html',msg=msg,act=act,data=data,name=name)
    
@app.route('/geo_location', methods=['GET', 'POST'])
def geo_location():
    data=""
    msg=""
    s1=""
    fid=request.args.get("fid")
    ctype=request.args.get("ctype")
    
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()

    mycursor.execute('SELECT count(*) FROM geo_location')
    cnt=mycursor.fetchone()[0]
    if cnt>0:
        s1="2"
    else:
        s1="1"
    
    return render_template('geo_location.html',fid=fid,ctype=ctype,s1=s1)

@app.route('/map', methods=['GET', 'POST'])
def map():
    msg=""
    fid=request.args.get("fid")
    ctype=request.args.get("ctype")
    mycursor = mydb.cursor()
    if request.method=='POST':
        detail=request.form['detail']
        location=request.form['location']

        #n1=len(detail)
        #n2=n1-3
        #value=detail[1:n2]
        #print(value)
        
        mycursor.execute("SELECT max(id)+1 FROM geo_location")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        
        sql = "INSERT INTO geo_location(id,location,detail) VALUES (%s, %s, %s)"
        val = (maxid,location,detail)
        act="success"
        mycursor.execute(sql, val)
        mydb.commit()
        msg="ok"

    mycursor.execute('SELECT * FROM geo_location order by id desc limit 0,1')
    view=mycursor.fetchone()
    
    return render_template('map.html',fid=fid,ctype=ctype,msg=msg,view=view)

@app.route('/map1', methods=['GET', 'POST'])
def map1():
    msg=""
    fid=request.args.get("fid")
    ctype=request.args.get("ctype")
    mycursor = mydb.cursor()
    if request.method=='POST':
        detail=request.form['detail']
        location=request.form['location']

        #n1=len(detail)
        #n2=n1-3
        #value=detail[1:n2]
        #print(value)
        
        mycursor.execute("SELECT max(id)+1 FROM geo_location")
        maxid = mycursor.fetchone()[0]
        if maxid is None:
            maxid=1

        
        sql = "INSERT INTO geo_location(id,location,detail) VALUES (%s, %s, %s)"
        val = (maxid,location,detail)
        act="success"
        mycursor.execute(sql, val)
        mydb.commit()
        msg="ok"

    mycursor.execute('SELECT * FROM geo_location order by id desc limit 0,1')
    view=mycursor.fetchone()
    
    return render_template('map1.html',fid=fid,ctype=ctype,msg=msg,view=view)




@app.route('/view_files', methods=['GET', 'POST'])
def view_files():
    msg=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    print(uname)

    cursor1 = mydb.cursor()
    cursor1.execute('SELECT * FROM va_register where uname=%s',(uname, ))
    rr=cursor1.fetchone()
    name=rr[1]

    cursor1.execute('SELECT * FROM va_user_files where uname=%s',(uname, ))
    data=cursor1.fetchall()

    if act=="del":
        did = request.args.get('did')
        cursor1.execute('delete from va_user_files where id=%s', (did,))
        mydb.commit()

    return render_template('view_files.html',msg=msg,name=name,data=data)

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    uname=""
    msg=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM data_owner where owner_id=%s",(uname,))
    value = mycursor.fetchone()
    dname=value[1]
    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
        
    if request.method=='POST':
        
        name=request.form['name']
        gender=request.form['gender']
        dob=request.form['dob']
        mobile=request.form['mobile']
        email=request.form['email']
        user=request.form['user']
        
        location=request.form['location']
        designation=request.form['designation']

        pw=randint(10000,99999)
        pass1=str(pw)

        mycursor.execute('SELECT count(*) FROM data_user WHERE username = %s ', (user,))
        cnt = mycursor.fetchone()[0]
        if cnt==0:
            dbb=dob.split('-')
            dob1=dbb[2]+"-"+dbb[1]+"-"+dbb[0]
            
            mycursor.execute("SELECT max(id)+1 FROM data_user")
            maxid = mycursor.fetchone()[0]
            if maxid is None:
                maxid=1

            
            sql = "INSERT INTO data_user(id, name, owner_id, gender, dob, mobile, email,location, designation, username, password) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid, name, uname, gender, dob1, mobile, email, location, designation, user, pass1)
            act="success"
            mycursor.execute(sql, val)
            mydb.commit()            
            print(mycursor.rowcount, "record inserted.")
            ##send mail
            message="User Account - Data Owner:"+uname+", Username: "+user+", Password: "+pass1
            url="http://iotcloud.co.in/testmail/testmail1.php?email="+email+"&message="+message
            webbrowser.open_new(url)
            act="1"
            msg="success"
        else:
            msg="fail"

    mycursor.execute("SELECT * FROM data_user where owner_id=%s",(uname,))
    data = mycursor.fetchall()
    
    return render_template('add_user.html',act=act,data=data,msg=msg)



@app.route('/share', methods=['GET', 'POST'])
def share():
    fid=request.args.get("fid")
    uname=""
    msg=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM data_owner where owner_id=%s",(uname,))
    value = mycursor.fetchone()
    name=value[1]

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")

    mycursor.execute("SELECT * FROM data_user where owner_id=%s",(uname,))
    udata = mycursor.fetchall()

    mycursor.execute("SELECT count(*) FROM data_user where owner_id=%s",(uname,))
    ucnt = mycursor.fetchone()[0]

    mycursor.execute("SELECT * FROM data_files where id=%s",(fid,))
    fdata = mycursor.fetchone()
    fname=fdata[3]

    if request.method=='POST':
        
        uu=request.form.getlist('uu[]')

        for u1 in uu:
            mycursor.execute("SELECT max(id)+1 FROM data_share")
            maxid = mycursor.fetchone()[0]
            if maxid is None:
                maxid=1

            
            sql = "INSERT INTO data_share(id, owner_id, fid, username, share_type, share_date) VALUES (%s, %s, %s, %s, %s, %s)"
            val = (maxid, uname, fid, u1, '1', rdate)
            act="success"
            mycursor.execute(sql, val)
            mydb.commit()            
            
        msg="success"


    mycursor.execute("SELECT * FROM data_files a,data_share b where a.owner_id=%s && a.id=b.fid && b.share_type=1 order by b.id desc",(uname,))
    data = mycursor.fetchall()
    
    return render_template('share.html',act=act,udata=udata,msg=msg,fid=fid,fdata=fdata,ucnt=ucnt,name=name,data=data)

#ChaCha20 Encryption
import struct

def yield_chacha20_xor_stream(key, iv, position=0):
  """Generate the xor stream with the ChaCha20 cipher."""
  if not isinstance(position, int):
    raise TypeError
  if position & ~0xffffffff:
    raise ValueError('Position is not uint32.')
  if not isinstance(key, bytes):
    raise TypeError
  if not isinstance(iv, bytes):
    raise TypeError
  if len(key) != 32:
    raise ValueError
  if len(iv) != 8:
    raise ValueError

  def rotate(v, c):
    return ((v << c) & 0xffffffff) | v >> (32 - c)

  def quarter_round(x, a, b, c, d):
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 16)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 12)
    x[a] = (x[a] + x[b]) & 0xffffffff
    x[d] = rotate(x[d] ^ x[a], 8)
    x[c] = (x[c] + x[d]) & 0xffffffff
    x[b] = rotate(x[b] ^ x[c], 7)

  ctx = [0] * 16
  ctx[:4] = (1634760805, 857760878, 2036477234, 1797285236)
  ctx[4 : 12] = struct.unpack('<8L', key)
  ctx[12] = ctx[13] = position
  ctx[14 : 16] = struct.unpack('<LL', iv)
  while 1:
    x = list(ctx)
    for i in range(10):
      quarter_round(x, 0, 4,  8, 12)
      quarter_round(x, 1, 5,  9, 13)
      quarter_round(x, 2, 6, 10, 14)
      quarter_round(x, 3, 7, 11, 15)
      quarter_round(x, 0, 5, 10, 15)
      quarter_round(x, 1, 6, 11, 12)
      quarter_round(x, 2, 7,  8, 13)
      quarter_round(x, 3, 4,  9, 14)
    for c in struct.pack('<16L', *(
        (x[i] + ctx[i]) & 0xffffffff for i in range(16))):
      yield c
    ctx[12] = (ctx[12] + 1) & 0xffffffff
    if ctx[12] == 0:
      ctx[13] = (ctx[13] + 1) & 0xffffffff


def chacha20_encrypt(data, key, iv=None, position=0):
  """Encrypt (or decrypt) with the ChaCha20 cipher."""
  if not isinstance(data, bytes):
    raise TypeError
  if iv is None:
    iv = b'\0' * 8
  if isinstance(key, bytes):
    if not key:
      raise ValueError('Key is empty.')
    if len(key) < 32:
      # TODO(pts): Do key derivation with PBKDF2 or something similar.
      key = (key * (32 // len(key) + 1))[:32]
    if len(key) > 32:
      raise ValueError('Key too long.')

  return bytes(a ^ b for a, b in
      zip(data, yield_chacha20_xor_stream(key, iv, position)))


'''assert chacha20_encrypt(
    b'Hello World', b'chacha20!') == b'\xeb\xe78\xad\xd5\xab\x18R\xe2O~'
assert chacha20_encrypt(
    b'\xeb\xe78\xad\xd5\xab\x18R\xe2O~', b'chacha20!') == b'Hello World'
'''

def run_tests():
  import binascii
  uh = lambda x: binascii.unhexlify(bytes(x, 'ascii'))
  for i, (ciphertext, key, iv) in enumerate((
      (uh('76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669'), uh('0000000000000000000000000000000000000000000000000000000000000000'), uh('0000000000000000')),
      (uh('4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41bbe2a0b6ea7566d2a5d1e7e20d42af2c53d792b1c43fea817e9ad275'), uh('0000000000000000000000000000000000000000000000000000000000000001'), uh('0000000000000000')),
      (uh('de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7fa5b5277062eb7a0433e445f41e3'), uh('0000000000000000000000000000000000000000000000000000000000000000'), uh('0000000000000001')),
      (uh('ef3fdfd6c61578fbf5cf35bd3dd33b8009631634d21e42ac33960bd138e50d32111e4caf237ee53ca8ad6426194a88545ddc497a0b466e7d6bbdb004'), uh('0000000000000000000000000000000000000000000000000000000000000000'), uh('0100000000000000')),
      (uh('f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f15916155c2be8241a38008b9a26bc35941e2444177c8ade6689de95264986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a475032b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c507b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f76dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb'), uh('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'), uh('0001020304050607')),
      )):
    assert chacha20_encrypt(b'\0' * len(ciphertext), key, iv) == ciphertext
    print('Test %d OK.' % i)
#######################
    
@app.route('/share2', methods=['GET', 'POST'])
def share2():
    fid=request.args.get("fid")
    uname=""
    msg=""
    data=[]
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM data_owner where owner_id=%s",(uname,))
    value = mycursor.fetchone()

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")

    mycursor.execute("SELECT * FROM data_user where owner_id=%s",(uname,))
    udata = mycursor.fetchall()

    mycursor.execute("SELECT count(*) FROM data_user where owner_id=%s",(uname,))
    ucnt = mycursor.fetchone()[0]

    mycursor.execute("SELECT * FROM geo_location")
    gdata = mycursor.fetchall()

    mycursor.execute("SELECT * FROM data_files where id=%s",(fid,))
    fdata = mycursor.fetchone()
    fname=fdata[3]

    mycursor.execute("SELECT * FROM data_share where fid=%s",(fid,))
    sdata = mycursor.fetchall()

    if request.method=='POST':
        location_id=request.form['location_id']
        uu=request.form.getlist('uu[]')

        for u1 in uu:
            mycursor.execute("SELECT count(*) FROM data_share where username=%s && fid=%s",(u1, fid))
            cnt1 = mycursor.fetchone()[0]
            if cnt1==0:
                
                mycursor.execute("SELECT max(id)+1 FROM data_share")
                maxid = mycursor.fetchone()[0]
                if maxid is None:
                    maxid=1

                
                sql = "INSERT INTO data_share(id, owner_id, fid, username, share_type, share_date) VALUES (%s, %s, %s, %s, %s, %s)"
                val = (maxid, uname, fid, u1, '2', rdate)
                act="success"
                mycursor.execute(sql, val)
                mydb.commit()

                #mycursor.execute("SELECT count(*) FROM share_location where username=%s && location_id=%s",(u1, location_id))
                #cnt = mycursor.fetchone()[0]
                #if cnt==0:
                mycursor.execute("SELECT max(id)+1 FROM share_location")
                maxid2 = mycursor.fetchone()[0]
                if maxid2 is None:
                    maxid2=1

                
                sql = "INSERT INTO share_location(id, username, share_type, share_id, location_id) VALUES (%s, %s, %s, %s, %s)"
                val = (maxid2, u1, '2', maxid, location_id)
                act="success"
                mycursor.execute(sql, val)
                mydb.commit()
            else:
                mycursor.execute("SELECT * FROM data_share where username=%s && fid=%s",(u1,fid))
                dd = mycursor.fetchone()
                share_id=dd[0]

                mycursor.execute("SELECT count(*) FROM share_location where username=%s && share_id=%s && location_id=%s",(u1,share_id,location_id ))
                cnt = mycursor.fetchone()[0]
                if cnt==0:
                    mycursor.execute("SELECT max(id)+1 FROM share_location")
                    maxid2 = mycursor.fetchone()[0]
                    if maxid2 is None:
                        maxid2=1

                    
                    sql = "INSERT INTO share_location(id, username, share_type, share_id, location_id) VALUES (%s, %s, %s, %s, %s)"
                    val = (maxid2, u1, '2', share_id, location_id)
                    act="success"
                    mycursor.execute(sql, val)
                    mydb.commit()
            
        msg="success"

    mycursor.execute("SELECT * FROM data_share where owner_id=%s && share_type=2 order by id desc",(uname,))
    dat = mycursor.fetchall()
    for d1 in dat:
        dt=[]
        fid=d1[2]
        mycursor.execute("SELECT * FROM data_files where id=%s",(fid,))
        dat1 = mycursor.fetchone()
    
        dt.append(dat1[0])
        dt.append(dat1[1])
        dt.append(dat1[2])
        dt.append(dat1[3])
        dt.append(dat1[4])
        dt.append(dat1[5])
        dt.append(dat1[6])
        dt.append(dat1[7])
        dt.append(dat1[8])
        dt.append(d1[0])
        dt.append(d1[1])
        dt.append(d1[2])
        dt.append(d1[3])
        dt.append(d1[4])
        dt.append(d1[5])
        dt.append(d1[6])
        dt.append(d1[7])
        dt.append(d1[8])
        dt.append(d1[9])
        dt.append(d1[10])

        dt1=[]
        mycursor.execute("SELECT * FROM share_location where share_id=%s",(d1[0],))
        dat2 = mycursor.fetchall()
        for d2 in dat2:
            dt11=[]
            mycursor.execute("SELECT * FROM geo_location where id=%s",(d2[4],))
            dat3 = mycursor.fetchone()
            dt11.append(d2[0])
            dt11.append(dat3[0])
            dt11.append(dat3[1])
            dt11.append(dat3[2])
            dt1.append(dt11)
        dt.append(dt1)
        data.append(dt)

    if act=="share":
        did=request.args.get("did")
        mycursor.execute('delete from share_location where id=%s', (did,))
        mydb.commit()
        
        msg="ok"

    if act=="del":
        did=request.args.get("did")

        mycursor.execute('delete from share_location where share_id=%s', (did,))
        mydb.commit()
        
        mycursor.execute('delete from data_share where id=%s', (did,))
        mydb.commit()
        msg="ok"

    return render_template('share2.html',act=act,udata=udata,msg=msg,fid=fid,fdata=fdata,ucnt=ucnt,gdata=gdata,data=data)

@app.route('/share3', methods=['GET', 'POST'])
def share3():
    fid=request.args.get("fid")
    uname=""
    msg=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM data_owner where owner_id=%s",(uname,))
    value = mycursor.fetchone()

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")

    mycursor.execute("SELECT * FROM data_user where owner_id=%s",(uname,))
    udata = mycursor.fetchall()

    mycursor.execute("SELECT count(*) FROM data_user where owner_id=%s",(uname,))
    ucnt = mycursor.fetchone()[0]

    mycursor.execute("SELECT * FROM data_files where id=%s",(fid,))
    fdata = mycursor.fetchone()
    fname=fdata[3]

    if request.method=='POST':
        sdd=request.form['sdate']
        edd=request.form['edate']
        shour=request.form['shour']
        smin=request.form['smin']
        ehour=request.form['ehour']
        emin=request.form['emin']
        
        dys=request.form.getlist('c1[]')
        uu=request.form.getlist('uu[]')

        stime=shour+":"+smin
        etime=ehour+":"+emin
        days=','.join(dys)

        sdd1=sdd.split('-')
        sdate=sdd1[2]+"-"+sdd1[1]+"-"+sdd1[0]
        edd1=edd.split('-')
        edate=edd1[2]+"-"+edd1[1]+"-"+edd1[0]
        
        
        for u1 in uu:
            mycursor.execute("SELECT max(id)+1 FROM data_share")
            maxid = mycursor.fetchone()[0]
            if maxid is None:
                maxid=1

            
            sql = "INSERT INTO data_share(id, owner_id, fid, username, share_type, share_date,sdate,edate,stime,etime,days) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            val = (maxid, uname, fid, u1, '3', rdate, sdate,edate,stime,etime,days)
            act="success"
            mycursor.execute(sql, val)
            mydb.commit()            
            
        msg="success"

    mycursor.execute("SELECT * FROM data_files a,data_share b where a.id=b.fid && b.share_type=3 order by b.id desc")
    data = mycursor.fetchall()

    return render_template('share3.html',act=act,udata=udata,msg=msg,fid=fid,fdata=fdata,ucnt=ucnt,data=data)

@app.route('/share4', methods=['GET', 'POST'])
def share4():
    fid=request.args.get("fid")
    uname=""
    msg=""
    act = request.args.get('act')
    if 'username' in session:
        uname = session['username']
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM data_owner where owner_id=%s",(uname,))
    value = mycursor.fetchone()

    now = datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")

    mycursor.execute("SELECT * FROM data_user where owner_id=%s",(uname,))
    udata = mycursor.fetchall()

    mycursor.execute("SELECT count(*) FROM data_user where owner_id=%s",(uname,))
    ucnt = mycursor.fetchone()[0]

    mycursor.execute("SELECT * FROM geo_location")
    gdata = mycursor.fetchall()

    mycursor.execute("SELECT * FROM data_files where id=%s",(fid,))
    fdata = mycursor.fetchone()
    fname=fdata[3]

    mycursor.execute("SELECT * FROM data_share where fid=%s",(fid,))
    sdata = mycursor.fetchall()

    if request.method=='POST':
        location_id=request.form['location_id']
        uu=request.form.getlist('uu[]')

        for u1 in uu:
            mycursor.execute("SELECT count(*) FROM data_share where username=%s && fid=%s",(u1, fid))
            cnt1 = mycursor.fetchone()[0]
            if cnt1==0:
                
                mycursor.execute("SELECT max(id)+1 FROM data_share")
                maxid = mycursor.fetchone()[0]
                if maxid is None:
                    maxid=1

                
                sql = "INSERT INTO data_share(id, owner_id, fid, username, share_type, share_date) VALUES (%s, %s, %s, %s, %s, %s)"
                val = (maxid, uname, fid, u1, '4', rdate)
                act="success"
                mycursor.execute(sql, val)
                mydb.commit()

                
                mycursor.execute("SELECT max(id)+1 FROM share_location")
                maxid2 = mycursor.fetchone()[0]
                if maxid2 is None:
                    maxid2=1

                
                sql = "INSERT INTO share_location(id, username, share_type, share_id, location_id) VALUES (%s, %s, %s, %s, %s)"
                val = (maxid2, u1, '4', maxid, location_id)
                act="success"
                mycursor.execute(sql, val)
                mydb.commit()

            else:
                
                mycursor.execute("SELECT * FROM data_share where username=%s && fid=%s",(u1,fid))
                dd = mycursor.fetchone()
                share_id=dd[0]
                
                mycursor.execute("update share_location set location_id=%s where username=%s && share_id=%s",(location_id,u1,share_id))
                mydb.commit()
            
        msg="success"

    mycursor.execute("SELECT * FROM data_files a,data_share b where a.id=b.fid && b.share_type=4 order by b.id desc")
    data = mycursor.fetchall()

    if act=="del":
        did = request.args.get('did')
        
        cursor1.execute('delete from data_share where id=%s', (did,))
        mydb.commit()
        msg="ok"
    if act=="share":
        did = request.args.get('did')
        cursor1.execute('delete from share_location where id=%s', (did,))
        mydb.commit()
        
        msg="ok"

    return render_template('share4.html',act=act,udata=udata,msg=msg,fid=fid,fdata=fdata,ucnt=ucnt,gdata=gdata,data=data)

@app.route('/userhome', methods=['GET', 'POST'])
def userhome():
    msg=""
    fdata=""
    data=[]
    act=request.args.get("act")
    fid=request.args.get("fid")
    fn=request.args.get("fn")
    
    view=""
    if 'username' in session:
        uname = session['username']
    print(uname)

    mycursor = mydb.cursor()
    mycursor.execute('SELECT * FROM data_user where username=%s',(uname, ))
    rr=mycursor.fetchone()
    name=rr[1]
    owner=rr[2]

    ff=open("static/geo.txt","r")
    loc=ff.read()
    ff.close()
    loc1=loc.split('|')
    lat=loc1[0]
    lon=loc1[1]

    now = date.today() #datetime.datetime.now()
    rdate=now.strftime("%d-%m-%Y")
    cd1=rdate.split('-')

    import datetime
    now1 = datetime.datetime.now()
    rtime=now1.strftime("%H:%M")
    #print(rtime)
    
    rtime1=rtime.split(':')
    rh=int(rtime1[0])
    rm=int(rtime1[1])
    #########
    mycursor.execute("SELECT count(*) FROM data_files f,data_share s where s.fid=f.id && s.username=%s",(uname,))
    c1 = mycursor.fetchone()[0]
    if c1>0:
        
        mycursor.execute("SELECT * FROM data_files f,data_share s where s.fid=f.id && s.username=%s",(uname,))
        dat = mycursor.fetchall()
        for d1 in dat:
            status=''
            if d1[13]==1:
                status='1'
    
            if d1[13]==2:
                lat1=lat.split('.')
                lt1=lat1[0]
                lt11=lat1[1]
                lt2=lt11[0:4]

                lon1=lon.split('.')
                lo1=lon1[0]
                lo2=lon1[1]
                
                mycursor.execute("SELECT * FROM share_location where share_id=%s",(d1[9],))
                d33 = mycursor.fetchall()
                for d3 in d33:

                    mycursor.execute("SELECT * FROM geo_location where id=%s",(d3[4],))
                    d4 = mycursor.fetchone()
                    g1=d4[2]
                    #print(g1)
                    g2=g1.split('new google.maps.LatLng(')
                    g21=''.join(g2)
                    g22=g21.split('), ')
                    g23='-'.join(g22)
                    g24=g23.split('-')
                    gn=len(g24)-1
                    i=0
                    geo1=''
                    geo2=''
                    gloc1=[]
                    gloc2=[]
                    while i<gn:
                        #print(g24[i])
                        gg=g24[i].split(',')
                        
                        l1=gg[0]
                        l2=gg[1]

                        f1=l1.split('.')
                        geo1=f1[0]
                        f2=f1[1]
                        f3=f2[0:4]
                        gloc1.append(f3)

                        h1=l2.split('.')
                        geo2=h1[0]
                        h2=h1[1]
                        h3=h2[0:4]
                        gloc2.append(f3)
                        
                        i+=1

                    ##
                    gloc1.sort()
                    #print(gloc1)
                    gn=len(gloc1)-1
                    gn1=gloc1[0]
                    gn2=gloc1[gn]

                    #print(lt1)
                    #print(lt2)
                    #print(lo1)
                    #print(gn1)
                    #print(gn2)
                    if lt1==geo1 and lo1==geo2:
                        if gn1<=lt2 and lt2<=gn2:
                            status="1"
                            #print("geo")
                            break
                    #status='1'
                
            if d1[13]==3:
                
                date_st=''
                time_st=''
                days_st=''
                #between date
                sdate=d1[15]
                edate=d1[16]
                sd1=sdate.split('-')
                ed1=sdate.split('-')
                import datetime
                sdd = datetime.datetime(int(sd1[2]), int(sd1[1]),int(sd1[0]))
                cdd = datetime.datetime(int(cd1[2]), int(cd1[1]),int(cd1[0]))
                edd = datetime.datetime(int(ed1[2]), int(ed1[1]),int(ed1[0]))
                #print(d1<d2<d3)
                #print(d2<d1<d3)   

                if sdd<cdd<edd:
                    date_st='1'
                else:
                    date_st='1'

                #bt time
                stt=d1[17]
                ett=d1[18]
                stt1=stt.split(':')
                ett1=ett.split(':')
                sh=int(stt1[0])
                sm=int(stt1[1])

                eh=int(ett1[0])
                em=int(ett1[1])
                
                s=0
                ###Check time
                if sh<=rh and rh<=eh:
                    if sh==eh:
                        if sm<=rm and rm<=em:
                            s+=1
                    elif sh==rh:
                        if sm<rm:
                            x+=1
                            
                    elif sh<rh and rh<eh:
                        if rm<=60:
                            s+=1
                    elif rh==eh:
                        if rm<=em:
                            s+=1
                    
                if s>0:
                    #print("aaaaa")
                    time_st='1'
                else:
                    print("not match")
                #print("time###")
                #print(time_st)
                #days
                dys=d1[19]
                dy=dys.split(',')
                x=0
                from datetime import datetime
                dty = datetime.now()
                ddy=dty.strftime('%A')
                ddr=['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday']
                i=0
                for ddr1 in ddr:
                    i+=1
                    if ddr1==ddy:
                        
                        break
                cdy=str(i)
                #print(cdy)
                for dy1 in dy:
                    if cdy==dy1:
                        x+=1
                if x>0:
                    days_st='1'

                #print(date_st)
                #print(time_st)
                #print(days_st)

                if date_st=='1' and time_st=='1' and days_st=='1':
                    status='1'
                else:
                    status='2'

            
            if d1[13]==4:
                
                ##########
                #lat="10.8284"
                #lon="78.6924"
                #print(lat)
                #print(lon)
                lat1=lat.split('.')
                lt1=lat1[0]
                lt11=lat1[1]
                lt2=lt11[0:4]

                lon1=lon.split('.')
                lo1=lon1[0]
                lo2=lon1[1]
                
                mycursor.execute("SELECT * FROM share_location where share_id=%s",(d1[9],))
                d3 = mycursor.fetchone()
                

                mycursor.execute("SELECT * FROM geo_location where id=%s",(d3[4],))
                d4 = mycursor.fetchone()
                g1=d4[2]
                #print(g1)
                g2=g1.split('new google.maps.LatLng(')
                g21=''.join(g2)
                g22=g21.split('), ')
                g23='-'.join(g22)
                g24=g23.split('-')
                gn=len(g24)-1
                i=0
                geo1=''
                geo2=''
                gloc1=[]
                gloc2=[]
                while i<gn:
                    #print(g24[i])
                    gg=g24[i].split(',')
                    
                    l1=gg[0]
                    l2=gg[1]

                    f1=l1.split('.')
                    geo1=f1[0]
                    f2=f1[1]
                    f3=f2[0:4]
                    gloc1.append(f3)

                    h1=l2.split('.')
                    geo2=h1[0]
                    h2=h1[1]
                    h3=h2[0:4]
                    gloc2.append(f3)
                    
                    i+=1

                ##
                gloc1.sort()
                #print(gloc1)
                gn=len(gloc1)-1
                gn1=gloc1[0]
                gn2=gloc1[gn]

                #print(lt1)
                #print(lt2)
                #print(lo1)
                #print(gn1)
                #print(gn2)
                if lt1==geo1 and lo1==geo2:
                    if gn1<=lt2 and lt2<=gn2:
                        status="1"
                        #print("geo")
                
                
                ##########
                #status='1'

            print(status)
            dt=[]
            dt.append(d1[0])
            dt.append(d1[1])
            dt.append(d1[2])
            dt.append(d1[3])
            dt.append(d1[4])
            dt.append(d1[5])
            dt.append(d1[6])
            dt.append(d1[7])
            dt.append(d1[8])
            dt.append(d1[9])
            dt.append(d1[10])
            dt.append(d1[11])
            dt.append(d1[12])
            dt.append(d1[13])
            dt.append(d1[14])
            dt.append(d1[15])
            dt.append(d1[16])
            dt.append(d1[17])
            dt.append(d1[18])
            dt.append(d1[19])
            dt.append(status)
            data.append(dt)
            

    
    #cursor.execute("SELECT * FROM data_files f,data_share s where s.fid=f.id && s.username=%s",(uname,))
    #data = cursor.fetchall()


    if act=="view":
        view="1"
        ff=open("static/data/"+fn,"r")
        fdata=ff.read()
        ff.close()
    

    return render_template('userhome.html',msg=msg,act=act,name=name,data=data,view=view,fdata=fdata)



@app.route('/down', methods=['GET', 'POST'])
def down():
    fid = request.args.get('fid')
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM data_files where id=%s",(fid,))
    value = mycursor.fetchone()
    path="static/upload/"+value[3]
    return send_file(path, as_attachment=True)

@app.route('/down1', methods=['GET', 'POST'])
def down1():
    fid = request.args.get('fid')
    mycursor = mydb.cursor()
    mycursor.execute("SELECT * FROM data_files where id=%s",(fid,))
    value = mycursor.fetchone()
    path="static/data/"+value[3]
    return send_file(path, as_attachment=True)


@app.route('/logout')
def logout():
    # remove the username from the session if it is there
    session.pop('username', None)
    return redirect(url_for('index'))




if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)

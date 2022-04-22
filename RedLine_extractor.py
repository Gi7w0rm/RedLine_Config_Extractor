import requests
import sys
import json
import pyzipper 
import keys
import os
import csv
from os import walk
import shutil
import time
from pathlib import Path
import concurrent.futures
import hashlib

UNPAC_ME_KEY = "Key "+keys.unpac_me_key
UNPAC_ME_URL_BASE = 'https://api.unpac.me/api/v1'
UNPAC_RATE_LIMIT = 5
UNPAC_ME_HEADER = {'Authorization' : UNPAC_ME_KEY}
#######################################################################

ZIP_PASSWORD = b'infected'
API_Key = keys.malware_bzr_key 
headers = { 'API-KEY': API_Key }

#######################################################################
#PATH_TO_SAMPLE = "/home/ubuntu/Schreibtisch/RedLine_MassDecoder/RedLine_samples"
#PATH_TO_SAMPLE = "/home/ubuntu/Schreibtisch/Unpacked_RedLine_Children"
#PATH_TO_SAMPLE = "/home/ubuntu/Schreibtisch/bazaar_redline"
#PATH_TO_SAMPLE = "/home/ubuntu/Schreibtisch/Uploaded_RedLine"
PATH_TO_SAMPLE = "/home/ubuntu/Schreibtisch/config_extracted_RedLine" #Path where all your juicy samples lay. You see I had quite a mess of folders and samples ^^
#PATH_TO_SAMPLE = "/home/ubuntu/Schreibtisch/MANUAL"
#######################################################################
PATH_TO_SUCCESS = "/home/ubuntu/Schreibtisch/config_extracted_RedLine" #Path where succesfull extracted samples go

PATH_TO_LOST = "/home/ubuntu/Schreibtisch/Lost_forever_RedLine" # Path where failed samples go

PATH_TO_UPLOADED = "/home/ubuntu/Schreibtisch/Uploaded_RedLine" # Path where samples go that have been uploaded to unpac me, as they will be replaced by unpacked samples

PATH_TO_CHILDREN = "/home/ubuntu/Schreibtisch/Unpacked_RedLine_Children" # Path for unpaced samples
PATH_TO_MANUAL = "/home/ubuntu/Schreibtisch/MANUAL" # Path to shit you need to look at manually, mainly because the config extraction did only yield partial results but not fully fail.

########################################################################

def get_file_names(pts):
    f = []
    for (dirpath, dirnames, filenames) in walk(pts):
        f.extend(filenames)
        break
    #print(f)
    return f


def get_hashes_by_yara(yara_name):
    data = {
    'query': 'get_yarainfo',
    'yara_rule': yara_name,
    'limit' : '1000'
    }
    response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, timeout=15, headers=headers, allow_redirects=True)
    #rest = response.text()
    rjson = response.json()
    dats = rjson['data']
    #print(dats)
    hashes = []
    for a in dats:
        hashes.append(a['sha256_hash'])
        #print(a['sha256_hash'])
    #print(hashes)
    return hashes

def filter_hashes(harray1, harray2, harray3, harray4):
    final_harray = []
    for ha in harray1:
        if ha in harray2:
            if ha in harray3:
                if ha in harray4:
                    #print(ha)
                    final_harray.append(ha)
    return final_harray

def get_samples(hash_array):
    for sha256 in hash_array:
        ddata = {
            'query' : 'get_file',
            'sha256_hash' : sha256,
        }
        fdload_response = requests.post('https://mb-api.abuse.ch/api/v1/', data=ddata, timeout=15, headers=headers, allow_redirects=True)
        if 'file_not_found' in fdload_response.text:
            print("Error: file not found")
            #sys.exit()
        else:
            open( "RedLine_samples/"+ sha256+'.zip', 'wb').write(fdload_response.content)
            with pyzipper.AESZipFile("RedLine_samples/" + sha256+".zip") as zf:
                zf.pwd = ZIP_PASSWORD
                my_secrets = zf.extractall("RedLine_samples/")  
                print("Sample \""+sha256+"\" downloaded and unpacked.")
            
            if os.path.exists("RedLine_samples/"+ sha256+ '.zip'):
                os.remove("RedLine_samples/"+ sha256+'.zip')
            else:
                print("The file does not exist") 

def move_samples(file_name, PATH_TO_SAMPLE, PATH_OF_DEST):
    #If we extract configs sucessfull, we move them to another folder
    src = PATH_TO_SAMPLE +"/" +file_name
    dst = PATH_OF_DEST+"/" +file_name
    try:
        shutil.move(src, dst)
        print("Moved")
        return True
    except:

        print("Couldn't move sample")
        print(src)
        print("to ")
        print(dst)
        exit() 
        return False


def check_unpac_me_by_id(ID_of_Upload):
    IDU = ID_of_Upload
    url_c = UNPAC_ME_URL_BASE + "/private/status/"+ ID_of_Upload
    
    status_return = None
    while(status_return == None):
        time.sleep(60)
        status_r = requests.get(url_c, headers  = UNPAC_ME_HEADER )    
    
        json_status = status_r.json()
        print(json_status["status"])   
        if json_status["status"] == "complete":
            status_return = True
            
        elif json_status["status"] == "fail":
            status_return = False
    
    return status_return

def upload_unpac_me(hash_tu):
    file_to_upload = hash_tu
    sample_path = PATH_TO_SAMPLE + "/" + file_to_upload
    file_data = None 
    with open(sample_path, "rb") as f:
        file_data = f.read()
    
    files = {'file': (file_to_upload, file_data)}
    r = requests.post('https://api.unpac.me/api/v1/private/upload', files=files, headers= UNPAC_ME_HEADER)    
    if not r.ok:
        print("Failed request:" + r.text)
    else:
        response = r.json()
        print(response["id"])
        return response["id"]

def get_unpac_result(idud):
    #https://api.unpac.me/api/v1/private/results/{unpack_id}
    ID_of_Upload = idud
    url_for_result = UNPAC_ME_URL_BASE + "/private/results/" + ID_of_Upload
    resp_result = requests.get(url_for_result, headers = UNPAC_ME_HEADER)
    #https://api.unpac.me/api/v1/private/search/hash/{sample_hash}
    print(resp_result)
    if not resp_result.ok:
        print("Error with finding Result.")
        exit()
    else: 
        j_resp_result = resp_result.json()
        #print(j_resp_result)
        print(j_resp_result["sha256"])
        url_to_search_hash = UNPAC_ME_URL_BASE + "/private/search/hash/" + j_resp_result["sha256"]
        r_child_answer = requests.get(url_to_search_hash, headers = UNPAC_ME_HEADER)
        if not r_child_answer.ok:
            print("Child answer not ok")
            exit()
        else:
            json_r_child_answer = r_child_answer.json()
            children = json_r_child_answer['results'][0]['children']
            #print(children)
            return children

def download_samples(list_of_hashes):

    list_to_download = list_of_hashes
    for h in list_to_download:    
        url = UNPAC_ME_URL_BASE + "/private/download/" + h
        r = requests.get(url, headers = UNPAC_ME_HEADER)
        #print(url)
        #print(r.status_code)
        #print(r.json())
        if not r.ok:
            print("Problem downloading")
            print(r.text)
        else:
            sample_data = r.content
            file_name = PATH_TO_CHILDREN + "/" + h
            path_init = Path(file_name)
            with open(file_name, "wb") as out:
                out.write(sample_data)
            if path_init.is_file():
                print("Downloading Sample "+ h + " successfull!")
            else:
                print("Download of sample " +str(h) + "failed!")
    return True


def get_config(hash_array):
    configs = []
    unsuccessfull_list = []
    n = 0
    array_length = str(len(hash_array))
    for sha256 in hash_array:
        
        path_to_malconf = "/home/ubuntu/Schreibtisch/RATDecoders/malconf"
        path_to_sample = PATH_TO_SAMPLE
        command = "python3 " + path_to_malconf + " " + path_to_sample +"/"+ sha256
        #.exe"
        #print(command)
        sample_config = os.popen(command).read()
        #print(sample_config)
        n = n + 1
        print("Current File:" + str(n) + " of " + array_length +" !")
        if "Config Output" in sample_config:
            confick = []

            try:
                conf_parts = sample_config.split("{")
                conf_part = conf_parts[1]
            #print(conf_part)
                conf_part_split = conf_part.split(",")
                c2 = str(conf_part_split[0])
                cid = str(conf_part_split[1])
                ckey_iugh = str(conf_part_split[2])
                #print(c2)
                ckeyp = ckey_iugh.split("}")
                ckey = ckeyp[0]
                clean_c2_p = c2.split(":")
            
                clean_c2 = clean_c2_p[1]
            
                c2_port = clean_c2_p[2]
                clean_cid_p = cid.split(":")
                clean_cid = clean_cid_p[1]
                clean_ckey_p = ckey.split(":")
                clean_ckey = clean_ckey_p[1]
                c2yport =  clean_c2+":"+c2_port
                #print(len(sha256))
                if len(sha256) != 64:
                    file_name = PATH_TO_SAMPLE + '/' + sha256
                    sha256_hash = hashlib.sha256()
                    with open(file_name,"rb") as f:
                        # Read and update hash string value in blocks of 4K
                        for byte_block in iter(lambda: f.read(4096),b""):
                            sha256_hash.update(byte_block)
                    sha256b = sha256_hash.hexdigest()
                else:
                    sha256b = sha256
                confick.append(sha256b)
                confick.append(c2yport)
                confick.append(clean_cid)
                confick.append(clean_ckey)
            #stringc = sha256+", "+clean_c2+":"+c2_port+", "+clean_cid+", "+clean_ckey
            #conf_string = stringc.replace(' ','')
                configs.append(confick)
                print("Success...Current sample: " + sha256)
                ToF = move_samples(sha256, PATH_TO_SAMPLE, PATH_TO_SUCCESS)
                if ToF == False:
                    exit()
            except IndexError as e:
                try:
                    if len(sha256) != 64:
                        file_name = PATH_TO_SAMPLE + '/' + sha256
                        sha256_hash = hashlib.sha256()
                        with open(file_name,"rb") as f:
                            # Read and update hash string value in blocks of 4K
                            for byte_block in iter(lambda: f.read(4096),b""):
                                sha256_hash.update(byte_block)
                        sha256b = sha256_hash.hexdigest()
                    else:
                        sha256b = sha256

                    c22 = str(conf_part_split[0])
                    cid2 = str(conf_part_split[1])    
                    clean_c2_p2 = c22.split(":")
            
                    clean_c22 = clean_c2_p2[1]
            
                    c2_port2 = clean_c2_p2[2]
                    clean_cid_p2 = cid2.split(":")
                    snc_clean_cid2 = clean_cid_p2[1]
                    snc2_clean_cid2 = snc_clean_cid2.split("}")
                    clean_cid2 = snc2_clean_cid2[0]
                    c2yport2 =  clean_c22+":"+c2_port2

                    
                    key2 = ""
                    if clean_cid2 == ' ""' or clean_cid2 == ' ""\n' or clean_cid2 == '""\n':
                        clean_cid2 = [NOT_YET_EXTRACTED]
                    confick.append(sha256b)
                    confick.append(c2yport2)
                    confick.append(clean_cid2)
                    confick.append(key2)
                    #print("Confiks: " + c22 + " and " + cid2)
                    print("Success...Current sample: " + sha256)
                    configs.append(confick)
                    ToF = move_samples(sha256, PATH_TO_SAMPLE, PATH_TO_SUCCESS)
                    if ToF == False:
                        exit()
                
                except Exception as e:

                    print(e)
                    print("Sample failed: " + sha256)
                    print("Config Parts not fully extracted!")
                    move_samples(sha256, PATH_TO_SAMPLE, PATH_TO_MANUAL)
            except UnboundLocalError as eul:
                print(eul)
                print("Sample is probably Mirai? " + sha256)


            #except IndexError as e:
            #    print("Sample failed: " + sha256)
            #    print("IndexError")
        elif "No Domain found, probably false detection by Regex" in sample_config:
            print("Broke out of loop")

        else:
            #print(sample_config)
            #n = n+1 
            #print(n)
            unsuccessfull_list.append(sha256)
    return configs, unsuccessfull_list

def unpac_me_handler(sha256_failed_sample):
    uploadid = upload_unpac_me(sha256_failed_sample)
    successfull_extraction = check_unpac_me_by_id(uploadid)
    if successfull_extraction == True:
               
        children_list = get_unpac_result(uploadid)
        print("successfull Unpacking")
        print(children_list)
        download_samples(children_list)
        move_samples(sha256_failed_sample,PATH_TO_SAMPLE,PATH_TO_UPLOADED)
        print("reached")
    else:
        print("No children for sample "+ sha256_failed_sample)
        #if len(children_found) == 0:
        #    #if children_found == False:
        move_samples(sha256_failed_sample, PATH_TO_SAMPLE, PATH_TO_LOST)
    return True
    

def write_csv(confs):
    header = ['SHA265', 'C2_Proxy', 'Campaign_ID', 'Enc_Key']

    with open('RedLine_configs.csv', 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)

    # write the header
        writer.writerow(header)

    # write multiple rows
        writer.writerows(confs)

    return True

if __name__ == "__main__":
    ################################################

    #ha1 = get_hashes_by_yara('RedLine')
    #ha2 = get_hashes_by_yara('redline_stealer')
    #ha3 = get_hashes_by_yara('redline_new_bin')
    #ha4 = get_hashes_by_yara('MALWARE_Win_RedLine')
    
    #ha5 = filter_hashes(ha1, ha2, ha3, ha4)
    #get_samples(ha5)

    ###############################################

    ha5 = get_file_names(PATH_TO_SAMPLE)
        
    all_the_confs, unsuccess = get_config(ha5)
    print("Got " + str(len(all_the_confs))+ " Configs out of " + str(len(ha5))+ " Samples.")
    print(all_the_confs)

    ##############################################
    
    if write_csv(all_the_confs):
        print("Done!")
    
    ##############################################
    '''
    # We can use a with statement to ensure threads are cleaned up promptly
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    # Start the load operations and mark each future with its URL
        future_to_hash = {executor.submit(unpac_me_handler, sample_hash): sample_hash for sample_hash in unsuccess}
        for future in concurrent.futures.as_completed(future_to_hash):
            hashe = future_to_hash[future]
            try:
                data = future.result()
            except Exception as exc:
                print('%r generated an exception: %s' % (hashe, exc))
    '''

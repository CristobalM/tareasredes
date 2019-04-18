import datetime

class Log:

    def __init__(self, hostname,ip_respuesta, address):
        self.hostname=hostname
        self.ip_respuesta=ip_respuesta
        self.addres = address
        
    def server_log(self):
    
        host_name = self.hostname.pop().get_question()
        host_name_nob = host_name.replace("b","") #hostname sin b
        format_host_name = host_name_nob.translate(str.maketrans({"'":None}))
        arreglo=""
        i=1
        while len(self.ip_respuesta)>0:
            popped_element=self.ip_respuesta.pop()
            answer = popped_element.unpacked_answer
            arreglado='.'.join(map(str,answer))
            arreglo=arreglo+ "IP" +str(i) +": "+arreglado + "  "
            i+=1
        
        ips = arreglo

 
        currentDT = datetime.datetime.now() #tiempo actual
        str_currentDT = str(currentDT)      #tiempo actual en string

        formateado= str_currentDT + " IPOrigen:" + str(self.addres[0])+ " " + format_host_name + " " + "Respuestas: "+  ips +"\n"
        f = open("log.txt", "a")
        f.write(formateado)
        f.close()




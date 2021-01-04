from scapy.all import *
from multiprocessing import Process



def function_analysis(answered_values,unanswered_values):
    for sent,recieved in answered_values:
        if recieved.haslayer(TCP) and str(recieved[TCP].flags) == "18":
            print (str(sent[TCP].dport)+ " is OPEN!")
        elif recieved.haslayer(TCP) and str(recieved[TCP].flags) == "20":
            print (str(sent[TCP].dport)+ " is CLOSED!")
        elif recieved.haslayer(TCP) and str(recieved[TCP].flags) == "3":
            print (str(sent[TCP].dport)+ " is Filtered!")  
    for sent in unanswered_values:
        print (str(sent[TCP].dport)+ " is Filtered!")

if __name__ == "__main__":
    target_value=input("Please input the IP address :")
    target_value_int=target_value
    #target address sample format = '172.16.1.2'
    minimum_port_number=input("Minimum port Number :")
    minimum_port_number_int=int(minimum_port_number)
    maximum_port_number=input("Maximum port Number :")
    maximum_port_number_int=int(maximum_port_number)
    maximum_port_number_int1=int(maximum_port_number_int/2)
    answered_values,unanswered_values = sr(IP(dst=target_value_int)/TCP(sport=RandShort(),dport= list(range(minimum_port_number_int, maximum_port_number_int1)),flags="S"),timeout=5)
    answered_values1,unanswered_values1 = sr(IP(dst=target_value_int)/TCP(sport=RandShort(),dport= list(range(maximum_port_number_int1, maximum_port_number_int)),flags="S"),timeout=5)
    p = Process(target=function_analysis, args=(answered_values,unanswered_values,))
    p.start()
    p.join()
    p1 = Process(target=function_analysis, args=(answered_values1,unanswered_values1,))
    p1.start()
    p.join()
    p1.join()

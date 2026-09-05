import json
from collections import defaultdict

def log_file_creation():
    with open("psh_python_webserver_2020-10-2900161507.json", "r", encoding="utf-8") as log_file:
        log_file_as_list = []
        for line in log_file:
            aktualna_linijka = json.loads(line)
            log_file_as_list.append(aktualna_linijka)
    return log_file_as_list

def create_counter(log_file_as_list):
    counter = defaultdict(int)
    for line in log_file_as_list:
        aktualne_id = line["EventID"]
        counter[aktualne_id] += 1
    return counter

def show_n_events(log_file_as_list, amount_to_show):
    #wypisuje n eventow liczach od 0
    for line in log_file_as_list[:amount_to_show]:
        print(line)

def id_appearence(counter, desired_id):
    return(f"ID {desired_id} pojawilo sie {counter[desired_id]} razy.")

def id_najczestsze(counter):
    top_amount = 0
    top_id = 0
    for event_id, amount in counter.items():
        if amount > top_amount:
            top_amount = amount
            top_id = event_id
    return(f"Najczestsze ID to {top_id} i pojawilo sie {top_amount} razy.")

def id_threat(log_file_as_list, suspected_threats):
    #numeracja linijek zaczyna sie od 0
    higher_threat = defaultdict(lambda: {"ilosc": 0, "linijka nr: ": []})
    for numer,line in enumerate(log_file_as_list,start=0):
        aktualne_id = line["EventID"]
        if aktualne_id in suspected_threats.keys():
            higher_threat[aktualne_id]["ilosc"] += 1
            higher_threat[aktualne_id]["linijka nr: "].append(numer)
    return higher_threat

#trzeba zmienic zeby nie brala za argument jeden event, a nie wczytywala cale logi
def important_data_extraction(line_number):
    line = log_file_as_list[line_number]
    event_id = line["EventID"]
    extracted_data = {}
    for key_word in suspected_threats[event_id]:
        extracted_data[key_word]=line[key_word]
    return extracted_data

if __name__ == "__main__":
    suspected_threats = {4688: ['NewProcessName','CommandLine','ParentProcessName','SubjectUserName',
                               'TargetLogonId','TokenElevationType', 'MandatoryLabel','ProcessId'],

                        1:     ['Image','CommandLine','ParentImage','User',
                               'Hashes','OriginalFileName','ParentCommandLine']}

    log_file_as_list = log_file_creation()
    counter = create_counter(log_file_as_list)
    #print(id_appearence(counter, 5158))
    #print(id_najczestsze(counter))
    print(id_threat(log_file_as_list, suspected_threats))
    #show_n_events(log_file_as_list, 3)
    print(log_file_as_list[3])
    print(important_data_extraction(3))
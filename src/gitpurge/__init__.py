import json 

def main() -> None:
    file = open("test/sample.json",'r')
    data = json.load(file)

    print(data)

if __name__ == "__main__":
    main()

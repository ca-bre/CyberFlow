import sys
import json

def main():
    # The second command-line argument might be JSON
    # e.g. python my_script.py '{"some":"data"}'
    data_str = sys.argv[1] if len(sys.argv) > 1 else "{}"
    data = json.loads(data_str)
    # do some Python logic
    result = {"message": "Hello from Python!", "received": data}
    # print JSON back to Node
    print(json.dumps(result))

if __name__ == "__main__":
    main()
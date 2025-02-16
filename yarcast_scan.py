import argparse
import json
import os
import sys
import yara
import yarcast_collect as collector
import functools
from rich.console import Console
from rich.table import Table
from rich.progress import track

# {rulename, reason}
problem_rules = {}
last_problem_rule = ""

def print_json(analysis):
    print(json.dumps(analysis, indent=4))

def print_plain(analysis):
    for k, v in analysis.items():
        print(k + ":", v)

def scan_with_repos(sample, yara_dirs, verbose=False):
    """Scans a sample with multiple repositories"""
    matches = dict() # { repo_name : match_list }
    blocklist = load_blocklist()
    for yara_dir in track(yara_dirs):
       result = scan_with_repo(sample, yara_dir, blocklist, verbose)
       if len(result) > 0:
           matches[yara_dir] = result
    return matches
        
def scan_with_repo(sample, repo, blocklist, verbose=False):
    matches = []
    for subdir, _, files in os.walk(repo):
        for file in files:
            sigfile = os.path.join(subdir, file)
            if verbose: print('found', sigfile)
            try:
                scan_result = scan_with_sigfile(sample, sigfile, blocklist)
                matches.extend(scan_result)
            except Exception as e:
                print('problem with scanning', sigfile)
                print('rule:', last_problem_rule)
                print('reason:', problem_rules[last_problem_rule])
                print('exception:', e)
    return matches

def warnings_callback(warning_type, message):
    global problem_rules
    global last_problem_rule
    last_problem_rule = message.rule
    if warning_type == yara.CALLBACK_TOO_MANY_MATCHES:
        sys.stderr.write(f"too many matches for rule:'{message.rule}' string:'{message.string}', the rule will be ignored\n")
        problem_rules[message.rule] = "too many matches"
        return yara.CALLBACK_ABORT
    else:
        sys.stderr.write(f"something went wrong with:'{message.rule}' string:'{message.string}'\n")
        problem_rules[message.rule] = "problem with string" + message.string
        return yara.CALLBACK_CONTINUE

def scan_with_sigfile(sample, sigfile, blocklist):
    rules = yara.load(filepath=sigfile)
    matches = rules.match(sample, warnings_callback=warnings_callback, timeout=10)
    return matches

def print_matches(matches, print_strings=False, print_author=False):
    max_strings = 10

    def prep(str, max=40):
        if len(str) > max:
            str = str[:max] + '...'
        return str

    blocklist = load_blocklist()

    for repo_path, matchlist in matches.items():
        repo_name = os.path.basename(repo_path)
        table = Table(title=repo_name, min_width=150)
        table.add_column('Rule', style="cyan")
        if print_author: table.add_column('Author', style="magenta")
        table.add_column('Description', style="green")
        table.add_column('Strings')
        table_has_content = False        
        for match in matchlist:
            desc = "-"
            author = "-"
            if str(match.rule) in blocklist:
                continue
            table_has_content = True
            if 'description' in match.meta:
                desc = match.meta['description'].strip()
            elif 'family' in match.meta:
                desc = match.meta['family'].strip()
            if 'author' in match.meta:
                author = match.meta['author'].strip()
            elif 'autor' in match.meta:
                author = match.meta['autor'].strip()
            row = [str(match.rule)]
            if print_author:
                row.append(author)
            row.append(desc)
            
            match_strings = str(match.strings[1:-1]) if len(match.strings) >= 2 else str(match.strings)
            strings_elem = prep(match_strings) if not print_strings else ""

            row.append(strings_elem)
            table.add_row(*row)
            
            for var_name in match.strings:
                if print_strings:
                    # escape opening bracket so that rich does not interprete it as tag
                    all_inst = [str(i).replace('[','\\[') for i in var_name.instances]
                    inst_counts = list(set([i + f" [red]({all_inst.count(i)}x)" for i in all_inst]))
                    for i in inst_counts[:max_strings]:
                        string_row = ['', '', f"[bold]{prep(str(var_name))}: [yellow]{i}"]
                        if print_author: string_row = ['', '', '', f"[bold]{prep(str(var_name))}: [yellow]{i}"]
                        table.add_row(*string_row)
                    if len(inst_counts) > max_strings:
                        num = str(len(inst_counts) - max_strings)
                        snip_row = ['', '',  '[red]<and ' + num + ' more>']
                        if print_author: snip_row = ['', '', '',  '[red]<and ' + num + ' more>']
                        table.add_row(*snip_row)
        if table_has_content:
            console = Console()
            console.print(table)
        print()

def blocklist_rule(rule):
    """Adds a rule to the blocklist"""
    block_file = 'blocklist.txt'
    with open(block_file, 'a') as f:
        f.write(rule + '\n')

def read_total_rules():
    """Reads the total number of rules saved by collector last time"""
    total_rules_file = 'total_rules.txt'
    if not os.path.exists(total_rules_file):
        return 0
    with open(total_rules_file, 'r') as f:
        return int(f.read())

def load_blocklist():
    """Loads the blocklist"""
    block_file = 'blocklist.txt'
    if not os.path.exists(block_file):
        return []
    with open(block_file, 'r') as f:
        return f.read().splitlines()

def calc_number_of_matches(match_dict):
    """Calculates the number of matches"""
    return functools.reduce(lambda x, key:  len(match_dict[key]) + x, match_dict, 0)

def get_immediate_subdirectories(a_dir):
    """Gets the immediate subdirectories of a directory"""
    return [os.path.join(a_dir, name) for name in os.listdir(a_dir)
            if os.path.isdir(os.path.join(a_dir, name))]

def scan_single_sample(sample, args):
    """scans a single sample"""
    print('Analyzing sample', sample)
    print()
    repos = []
    repos.extend(get_immediate_subdirectories(collector.final_rules_dir))
    match_dict = scan_with_repos(sample, repos)
    num = calc_number_of_matches(match_dict)
    print()
    print_matches(match_dict, args.strings, args.author)
    print("Matches overall", num)
    print("Number of blocked rules", len(load_blocklist()))
    total_rules = read_total_rules()
    if total_rules > 0: print("Total number of rules", total_rules)
    print()
    
def main():
    parser = argparse.ArgumentParser(
        prog="yarcast_scan.py", 
        description="YARCAST - YARA Collection, Aggregation, Scanning, and Threat detection", 
        epilog="")
    
    parser.add_argument('sample', help="Sample to analyse")
    parser.add_argument('-s', '--strings', help="show matched string instances", action="store_true")
    parser.add_argument('-a', '--author', help="show author", action="store_true")
    parser.add_argument('-ab', '--auto_blocklist', help="automatically blocklist problematic rules", action="store_true")
    parser.add_argument('-b', '--blocklist_rule', help="puts rule name into a blocklist, so it is not used for scanning anymore", action="store_true")
    parser.add_argument('-v', '--verbose', help="verbose output", action="store_true")
    args = parser.parse_args()
    sample = args.sample

    if args.blocklist_rule:
        rule = args.sample
        blocklist_rule(rule)
        print("added", rule, "to blocklist")
        print("run the rules collector to compile without blocked rules and improve performance")
    elif os.path.isfile(sample):
        scan_single_sample(sample, args)
    elif os.path.isdir(sample):
        folder = sample
        for subdir, _, files in os.walk(folder):
            for file in files:
                afile = os.path.join(subdir, file)
                scan_single_sample(afile, args)
    else:
        sys.stderr.write("problem with reading " + sample)
    if args.auto_blocklist:
        if len(problem_rules) > 0:
            print("Auto blocklisting:")
        for rule in problem_rules.keys():
            blocklist_rule(rule)
            print("added", rule, "to blocklist")
            print("run the rules collector to compile without blocked rules and improve performance")

if __name__ == "__main__":
    main()
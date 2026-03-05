def write_results_file( results, file_path):
    with open(file_path, "w") as file:
        file.write(results)
# NuvlaEdge Agent Unit Tests

This folder contains all the unit tests available for the NuvlaEdge Agent. For each Agent module, there is a respective 
test file, where each module class and/or function is tested.

## Run the tests


To run the tests, make sure you've installed the dependencies from `requirements.tests.txt`:

```shell
# from the <project_root>/code folder
pip install -r requirements.tests.txt
```

and then run:

```shell
# from the <project_root>/code folder
python -m unittest tests/test_<filename>.py -v
```

or, if a report is needed:

```shell
pytest --junitxml=test-report.xml
```

## Run tests with coverage

To run tests and obtain the code coverage results for browsing in HTML format,
run the following command. The command uses the default configuration
file `.coveragerc` located in the same folder. Update if needed or provide
configuration parameters on CLI.

```shell
pytest --cov=agent --cov-report=html --cov-branch
```

The code coverage results can be viewed under `htmlcov/` directory. To open on
macOS, run

```shell
open htmlcov/index.html
```

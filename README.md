
## Installation & Execution

The code runs in Python 3.7.4.

Execute the command, `python illumio_test.py` to run the unit tests.


### General algorithm & scope for improvement

<a href="https://imgbb.com/"><img src="https://i.ibb.co/sjTKBZx/Untitled-Diagram.png" alt="Untitled-Diagram" border="0"></a><br /><br />

I've tried to represent the rule set in the form of a trie (as show above). Any rule check is in the best case only 4 lookups away. It is much faster than manually checking for each rule (when it comes to a huge amount of data) because:

* The ruleset is pre-computed.
* Every data point (direction, protocol, and port) is hashed.
* Due to shortage of time, this approach has a few places where it can be made faster.
    * Such as, using ranges for ip address instead of a list, and
    * Using some form of serializing or compression to make the precomputed ruleset smaller in size.
    * This approach prefers network latency over memory.

I'm immensely interested in the work all the teams are doing. Below are my preferences in order.
* Platform team
* Data team
* Policy team




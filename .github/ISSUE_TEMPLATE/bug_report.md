name: Bug report
description: Something does not connect, spray, or behave. Include the self-test output.
labels: ["bug"]
body:
  - type: markdown
    attributes:
      value: |
        Most reports come down to one of three things: an untrusted certificate,
        more than one copy of the userscript running, or Omara not accepting.
        The template below is built to separate them in one pass — please fill
        every section; a report without the self-test output usually gets a
        second round-trip question instead of an answer.
  - type: textarea
    id: symptom
    attributes:
      label: What happened
      description: What you expected, what you got, and whether any scent fired at all (including the greeting).
      placeholder: |
        Expected: beach scent on page load, sweet on a correct answer.
        Got: nothing; console shows "Firefox can't establish a connection".
    validations:
      required: true
  - type: textarea
    id: selftest
    attributes:
      label: Self-test output
      description: 'Run `run.bat selftest` and paste the whole console output, including the stats line.'
      render: text
    validations:
      required: true
  - type: textarea
    id: bridge-log
    attributes:
      label: Bridge window log
      description: The lines printed in the bridge console around the time you reloaded Quizlet — especially `[down] client ... concurrent=N` and anything upstream.
      render: text
    validations:
      required: true
  - type: dropdown
    id: cert-trusted
    attributes:
      label: Is the certificate trusted in Firefox?
      description: 'about:preferences → Certificates → View Certificates → Authorities. The import must have "Identifying websites" ticked.'
      options:
        - Yes, imported with "Identifying websites" ticked
        - Imported but not sure which boxes were ticked
        - No
        - Not applicable (not using Firefox)
    validations:
      required: true
  - type: dropdown
    id: script-copies
    attributes:
      label: How many userscript managers / copies are enabled?
      description: Two enabled managers means two sockets per page and double scents. The bridge log's `concurrent=` count is the ground truth.
      options:
        - One manager, one copy
        - Multiple managers or copies enabled
        - Not sure
    validations:
      required: true
  - type: input
    id: versions
    attributes:
      label: Versions
      description: OlFacts tag (e.g. v1.0.0), Python (`py --version`), websockets (`py -m pip show websockets | findstr Version`), Firefox, Windows.
      placeholder: OlFacts v1.0.0, Python 3.13.5, websockets 16.0, Firefox 141, Windows 11
    validations:
      required: true
  - type: textarea
    id: extras
    attributes:
      label: Anything else
      description: Bridge flags you changed from defaults, non-default ports, certificate flavour used (`selfsigned` vs CA), ad-blockers, corporate TLS interception.

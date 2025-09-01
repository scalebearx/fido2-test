[INSTALL]
uv sync  

[TEST]
## Run One test
uv run pytest tests/test_ctap_get_assertion_request.py -v
uv run pytest tests/test_ctap_get_next_assertion_context.py -v
uv run pytest tests/test_ctap_keyring_device.py -v
uv run pytest tests/test_ctap_make_credential_request.py -v
uv run pytest tests/test_noop_ctap_user_verifier.py -v

## Run All Tests
uv run pytest tests -v

[RUN]
uv run main.py


[PROMPTS]
Requirements:
1. 不得更改 ctap_keyring_device 和 test 目錄下的檔案
2. 不得安裝任何額外的套件

Instructions:
1. 參考 ctap_keyring_device 和 test 目錄下的程式碼
2. 修改 main.py 並完成 Registration & Authentication 的流程
3. 可將一些重要的資料寫入 .log file, 以便觀察並了解交互的過程
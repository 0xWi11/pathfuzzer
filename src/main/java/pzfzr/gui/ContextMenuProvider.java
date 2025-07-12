package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import pzfzr.config.SwitchState;
import pzfzr.core.ValueReplacer;
import pzfzr.model.RequestResponseSaver;
import pzfzr.model.TableModel;
import pzfzr.model.OriginalRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

public class ContextMenuProvider implements ContextMenuItemsProvider {
    private final MontoyaApi api;
    private final ValueReplacer valueReplacer;
    private final TableModel tableModel;
    private final RequestResponseSaver requestResponseSaver;
    private final ExecutorService executor = Executors.newFixedThreadPool(5);
    private final AtomicInteger messageIdGenerator = new AtomicInteger(5000000);


    public ContextMenuProvider(MontoyaApi api, ValueReplacer valueReplacer, TableModel tableModel, RequestResponseSaver requestResponseSaver) {
        this.api = api;
        this.valueReplacer = valueReplacer;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // 只在有请求时显示菜单项
        Optional<MessageEditorHttpRequestResponse> messageEditor = event.messageEditorRequestResponse();
        if (messageEditor.isEmpty()) {
            return menuItems;
        }

        // 获取当前请求响应对象
        HttpRequestResponse requestResponse = messageEditor.get().requestResponse();
        if (requestResponse == null || requestResponse.request() == null) {
            return menuItems;
        }

        // 创建子菜单
        JMenu headerIntruderMenu = new JMenu("Path Fuzzer");

        // 添加各种测试选项
        JMenuItem allTests = new JMenuItem("Run All Tests");
        allTests.addActionListener(e -> {
            // 在后台线程中执行测试
            executor.submit(() -> {
                try {
                    int messageId = messageIdGenerator.getAndIncrement();
                    OriginalRequestResponse original = tableModel.createEntry(new OriginalRequestResponse(
                                    requestResponse.request().method(),
                                    requestResponse.request().url(),
                                    messageId,
                                    requestResponseSaver, api.logging())
                            ,messageId);

                    // 添加异常捕获 - 主要修改部分
                    if (original != null) {
                        // 运行所有测试
                        try {
                            HttpRequestResponse originalReqRes = api.http().sendRequest(requestResponse.request());
                            if (originalReqRes != null && originalReqRes.response() != null) {
                                original.setOriginalResponse(originalReqRes.response());
                            }
                            valueReplacer.collectRequestHeaders(requestResponse.request().headers());
                            valueReplacer.collectResponseHeaders(requestResponse.response().headers());
                        } catch (Exception ex) {
                            api.logging().logToError("[ContextMenuProvider] Error sending original request: " + ex.getMessage());
                        }
                        SwitchState allEnabledState = new SwitchState(true,true, true, true, true);
                        valueReplacer.unifiedTest(requestResponse.request(), allEnabledState, original.getMessageId());
                    } else {
                        api.logging().logToError("[ContextMenuProvider] Failed to create OriginalRequestResponse entry for messageId: " + messageId);
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[ContextMenuProvider] Error running all tests: " + ex.getMessage());
                }
            });
        });

        JMenuItem protoTest = new JMenuItem("Run JsonLister Test");
        protoTest.addActionListener(e -> {
            executor.submit(() -> {
                try {
                    int messageId = messageIdGenerator.getAndIncrement();
                    OriginalRequestResponse original = tableModel.createEntry(new OriginalRequestResponse(
                                    requestResponse.request().method(),
                                    requestResponse.request().url(),
                                    messageId,
                                    requestResponseSaver, api.logging())
                            ,messageId);

                    // 添加异常捕获
                    if (original != null) {
                        try {
                            HttpRequestResponse originalReqRes = api.http().sendRequest(requestResponse.request());
                            if (originalReqRes != null && originalReqRes.response() != null) {
                                original.setOriginalResponse(originalReqRes.response());
                            }
                            valueReplacer.collectRequestHeaders(requestResponse.request().headers());
                            valueReplacer.collectResponseHeaders(requestResponse.response().headers());
                        } catch (Exception ex) {
                            api.logging().logToError("[ContextMenuProvider] Error sending original request: " + ex.getMessage());
                        }
                        valueReplacer.JsonListerTest(requestResponse.request(),
                                original.getMessageId(),
                                valueReplacer.extractHostFromRequest(requestResponse.request().url()));
                    } else {
                        api.logging().logToError("[ContextMenuProvider] Failed to create OriginalRequestResponse entry for messageId: " + messageId);
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[ContextMenuProvider] Error running JsonListerTest: " + ex.getMessage());
                }
            });
        });

        JMenuItem collectedTest = new JMenuItem("Run RouteFuzzer Test");
        collectedTest.addActionListener(e -> {
            executor.submit(() -> {
                try {
                    int messageId = messageIdGenerator.getAndIncrement();
                    OriginalRequestResponse original = tableModel.createEntry(new OriginalRequestResponse(
                                    requestResponse.request().method(),
                                    requestResponse.request().url(),
                                    messageId,
                                    requestResponseSaver, api.logging())
                            ,messageId);

                    // 添加异常捕获
                    if (original != null) {
                        try {
                            HttpRequestResponse originalReqRes = api.http().sendRequest(requestResponse.request());
                            if (originalReqRes != null && originalReqRes.response() != null) {
                                original.setOriginalResponse(originalReqRes.response());
                            }
                            valueReplacer.collectRequestHeaders(requestResponse.request().headers());
                            valueReplacer.collectResponseHeaders(requestResponse.response().headers());
                        } catch (Exception ex) {
                            api.logging().logToError("[ContextMenuProvider] Error sending original request: " + ex.getMessage());
                        }
                        valueReplacer.RouteFuzzerTest(requestResponse.request(),
                                original.getMessageId(),
                                valueReplacer.extractHostFromRequest(requestResponse.request().url()));
                    } else {
                        api.logging().logToError("[ContextMenuProvider] Failed to create OriginalRequestResponse entry for messageId: " + messageId);
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[ContextMenuProvider] Error running RouteFuzzerTest: " + ex.getMessage());
                }
            });
        });

        JMenuItem suspiciousTest = new JMenuItem("Run Suspicious Test Only");
        suspiciousTest.addActionListener(e -> {
            executor.submit(() -> {
                try {
                    int messageId = messageIdGenerator.getAndIncrement();
                    OriginalRequestResponse original = tableModel.createEntry(new OriginalRequestResponse(
                                    requestResponse.request().method(),
                                    requestResponse.request().url(),
                                    messageId,
                                    requestResponseSaver, api.logging())
                            ,messageId);

                    // 添加异常捕获
                    if (original != null) {
                        try {
                            HttpRequestResponse originalReqRes = api.http().sendRequest(requestResponse.request());
                            if (originalReqRes != null && originalReqRes.response() != null) {
                                original.setOriginalResponse(originalReqRes.response());
                            }
                            valueReplacer.collectRequestHeaders(requestResponse.request().headers());
                            valueReplacer.collectResponseHeaders(requestResponse.response().headers());
                        } catch (Exception ex) {
                            api.logging().logToError("[ContextMenuProvider] Error sending original request: " + ex.getMessage());
                        }
                        valueReplacer.SuspiciousTest(requestResponse.request(),
                                original.getMessageId(),
                                valueReplacer.extractHostFromRequest(requestResponse.request().url()));
                    } else {
                        api.logging().logToError("[ContextMenuProvider] Failed to create OriginalRequestResponse entry for messageId: " + messageId);
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[ContextMenuProvider] Error running suspicious test: " + ex.getMessage());
                }
            });
        });

        JMenuItem knownTest = new JMenuItem("Run Known Test Only");
        knownTest.addActionListener(e -> {
            executor.submit(() -> {
                try {
                    int messageId = messageIdGenerator.getAndIncrement();
                    OriginalRequestResponse original = tableModel.createEntry(new OriginalRequestResponse(
                                    requestResponse.request().method(),
                                    requestResponse.request().url(),
                                    messageId,
                                    requestResponseSaver, api.logging())
                            ,messageId);

                    // 添加异常捕获
                    if (original != null) {
                        try {
                            HttpRequestResponse originalReqRes = api.http().sendRequest(requestResponse.request());
                            if (originalReqRes != null && originalReqRes.response() != null) {
                                original.setOriginalResponse(originalReqRes.response());
                            }
                            valueReplacer.collectRequestHeaders(requestResponse.request().headers());
                            valueReplacer.collectResponseHeaders(requestResponse.response().headers());
                        } catch (Exception ex) {
                            api.logging().logToError("[ContextMenuProvider] Error sending original request: " + ex.getMessage());
                        }
                        valueReplacer.KnownTest(requestResponse.request(),
                                original.getMessageId(),
                                valueReplacer.extractHostFromRequest(requestResponse.request().url()));
                    } else {
                        api.logging().logToError("[ContextMenuProvider] Failed to create OriginalRequestResponse entry for messageId: " + messageId);
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[ContextMenuProvider] Error running known test: " + ex.getMessage());
                }
            });
        });

        // 添加菜单项到子菜单
        headerIntruderMenu.add(allTests);
        headerIntruderMenu.addSeparator();
        headerIntruderMenu.add(protoTest);
        headerIntruderMenu.add(collectedTest);
        headerIntruderMenu.add(suspiciousTest);
        headerIntruderMenu.add(knownTest);  // 添加 Known Test 菜单项


        // 添加子菜单到列表
        menuItems.add(headerIntruderMenu);

        return menuItems;
    }

    // 确保在插件卸载时调用此方法
    public void shutdown() {
        executor.shutdown();
    }
}
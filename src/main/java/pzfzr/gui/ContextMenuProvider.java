package pzfzr.gui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import pzfzr.config.ConfigManager;
import pzfzr.config.FilterRule;
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
    private final ConfigManager configManager;
    private final ExecutorService executor = Executors.newFixedThreadPool(5);
    private final AtomicInteger messageIdGenerator = new AtomicInteger(5000000);

    public ContextMenuProvider(MontoyaApi api, ValueReplacer valueReplacer, TableModel tableModel, RequestResponseSaver requestResponseSaver) {
        this.api = api;
        this.valueReplacer = valueReplacer;
        this.tableModel = tableModel;
        this.requestResponseSaver = requestResponseSaver;
        this.configManager = ConfigManager.getInstance();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();

        // 获取当前请求响应对象 - 支持两种上下文
        HttpRequestResponse requestResponse = null;
        List<HttpRequestResponse> allSelectedRequests = new ArrayList<>();

        // 首先检查消息编辑器上下文（请求包内右键）
        Optional<MessageEditorHttpRequestResponse> messageEditor = event.messageEditorRequestResponse();
        if (messageEditor.isPresent() && messageEditor.get().requestResponse() != null) {
            requestResponse = messageEditor.get().requestResponse();
            allSelectedRequests.add(requestResponse);
        }
        // 然后检查选择的请求响应列表（HTTP history右键）
        else {
            List<HttpRequestResponse> selectedRequestResponses = event.selectedRequestResponses();
            if (!selectedRequestResponses.isEmpty()) {
                // 取第一个选中的请求用于测试功能
                requestResponse = selectedRequestResponses.get(0);
                // 保存所有选中的请求用于过滤功能
                allSelectedRequests.addAll(selectedRequestResponses);
            }
        }

        // 如果没有找到有效的请求响应，不显示菜单
        if (requestResponse == null || requestResponse.request() == null) {
            return menuItems;
        }

        // 为了在lambda中使用，创建final引用
        final HttpRequestResponse finalRequestResponse = requestResponse;
        final List<HttpRequestResponse> finalAllSelectedRequests = new ArrayList<>(allSelectedRequests);

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
                                    finalRequestResponse.request().method(),
                                    finalRequestResponse.request().url(),
                                    messageId,
                                    requestResponseSaver, api.logging())
                            ,messageId);

                    if (original != null) {
                        try {
                            HttpRequestResponse originalReqRes = api.http().sendRequest(finalRequestResponse.request());
                            if (originalReqRes != null && originalReqRes.response() != null) {
                                original.setOriginalResponse(originalReqRes.response());
                            }
                        } catch (Exception ex) {
                            api.logging().logToError("[ContextMenuProvider] Error sending original request: " + ex.getMessage());
                        }
                        SwitchState allEnabledState = new SwitchState(true,true, true, true, false);
                        valueReplacer.unifiedTestForContext(finalRequestResponse.request(), allEnabledState, original.getMessageId());
                    } else {
                        api.logging().logToError("[ContextMenuProvider] Failed to create OriginalRequestResponse entry for messageId: " + messageId);
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[ContextMenuProvider] Error running all tests: " + ex.getMessage());
                }
            });
        });

        // Add Filter 菜单项 - 修改为处理多个选中的请求
        JMenuItem addFilterItem = new JMenuItem("Add Filter");
        addFilterItem.addActionListener(e -> {
            try {
                List<String> addedUrls = new ArrayList<>();
                int successCount = 0;
                int errorCount = 0;

                for (HttpRequestResponse reqRes : finalAllSelectedRequests) {
                    try {
                        if (reqRes != null && reqRes.request() != null) {
                            String fullUrl = reqRes.request().url();

                            // 去掉?和后方的所有字符
                            String baseUrl = fullUrl.split("\\?")[0];

                            // 检查是否已经存在相同的过滤规则
                            boolean ruleExists = configManager.getFilterRules().stream()
                                    .anyMatch(rule -> rule.getValue().equals(baseUrl) &&
                                            rule.getType() == FilterRule.RuleType.URL &&
                                            rule.getMatchType() == FilterRule.RuleMatchType.CONTAINS);

                            if (!ruleExists) {
                                // 创建过滤规则，使用URL类型和CONTAINS匹配
                                FilterRule filterRule = new FilterRule(
                                        baseUrl,
                                        FilterRule.RuleType.URL,
                                        FilterRule.RuleMatchType.CONTAINS
                                );

                                // 添加到配置管理器
                                configManager.addFilterRule(filterRule);
                                addedUrls.add(baseUrl);
                                successCount++;

                                api.logging().logToOutput("[ContextMenuProvider] Added filter rule: " + baseUrl);
                            } else {
                                api.logging().logToOutput("[ContextMenuProvider] Filter rule already exists: " + baseUrl);
                            }
                        }
                    } catch (Exception ex) {
                        errorCount++;
                        api.logging().logToError("[ContextMenuProvider] Error processing request: " + ex.getMessage());
                    }
                }

                // 显示结果消息
                final int finalSuccessCount = successCount;
                final int finalErrorCount = errorCount;
                final int totalRequests = finalAllSelectedRequests.size();

                SwingUtilities.invokeLater(() -> {
                    String message;
                    int messageType;

                    if (finalErrorCount == 0) {
                        if (finalSuccessCount == totalRequests) {
                            message = String.format("Successfully added %d filter rule(s)", finalSuccessCount);
                        } else {
                            int duplicateCount = totalRequests - finalSuccessCount;
                            message = String.format("Added %d new filter rule(s). %d rule(s) already existed.",
                                    finalSuccessCount, duplicateCount);
                        }
                        messageType = JOptionPane.INFORMATION_MESSAGE;
                    } else {
                        message = String.format("Added %d filter rule(s), %d error(s) occurred",
                                finalSuccessCount, finalErrorCount);
                        messageType = JOptionPane.WARNING_MESSAGE;
                    }

                    JOptionPane.showMessageDialog(
                            null,
                            message,
                            "Filter Rules Added",
                            messageType
                    );
                });

            } catch (Exception ex) {
                api.logging().logToError("[ContextMenuProvider] Error adding filter rules: " + ex.getMessage());
                SwingUtilities.invokeLater(() -> {
                    JOptionPane.showMessageDialog(
                            null,
                            "Error adding filter rules: " + ex.getMessage(),
                            "Error",
                            JOptionPane.ERROR_MESSAGE
                    );
                });
            }
        });

        JMenuItem protoTest = new JMenuItem("Run JsonLister Test");
        protoTest.addActionListener(e -> {
            executor.submit(() -> {
                try {
                    int messageId = messageIdGenerator.getAndIncrement();
                    OriginalRequestResponse original = tableModel.createEntry(new OriginalRequestResponse(
                                    finalRequestResponse.request().method(),
                                    finalRequestResponse.request().url(),
                                    messageId,
                                    requestResponseSaver, api.logging())
                            ,messageId);

                    if (original != null) {
                        try {
                            HttpRequestResponse originalReqRes = api.http().sendRequest(finalRequestResponse.request());
                            if (originalReqRes != null && originalReqRes.response() != null) {
                                original.setOriginalResponse(originalReqRes.response());
                            }
                        } catch (Exception ex) {
                            api.logging().logToError("[ContextMenuProvider] Error sending original request: " + ex.getMessage());
                        }
                        valueReplacer.JsonListerTest(finalRequestResponse.request(),
                                original.getMessageId(),
                                valueReplacer.extractHostFromRequest(finalRequestResponse.request().url()));
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
                                    finalRequestResponse.request().method(),
                                    finalRequestResponse.request().url(),
                                    messageId,
                                    requestResponseSaver, api.logging())
                            ,messageId);

                    if (original != null) {
                        try {
                            HttpRequestResponse originalReqRes = api.http().sendRequest(finalRequestResponse.request());
                            if (originalReqRes != null && originalReqRes.response() != null) {
                                original.setOriginalResponse(originalReqRes.response());
                            }
                        } catch (Exception ex) {
                            api.logging().logToError("[ContextMenuProvider] Error sending original request: " + ex.getMessage());
                        }
                        valueReplacer.RouteFuzzerTest(finalRequestResponse.request(),
                                original.getMessageId(),
                                valueReplacer.extractHostFromRequest(finalRequestResponse.request().url()));
                    } else {
                        api.logging().logToError("[ContextMenuProvider] Failed to create OriginalRequestResponse entry for messageId: " + messageId);
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[ContextMenuProvider] Error running RouteFuzzerTest: " + ex.getMessage());
                }
            });
        });

        JMenuItem suspiciousTest = new JMenuItem("Run ParamFuzzer Test");
        suspiciousTest.addActionListener(e -> {
            executor.submit(() -> {
                try {
                    int messageId = messageIdGenerator.getAndIncrement();
                    OriginalRequestResponse original = tableModel.createEntry(new OriginalRequestResponse(
                                    finalRequestResponse.request().method(),
                                    finalRequestResponse.request().url(),
                                    messageId,
                                    requestResponseSaver, api.logging())
                            ,messageId);

                    if (original != null) {
                        try {
                            HttpRequestResponse originalReqRes = api.http().sendRequest(finalRequestResponse.request());
                            if (originalReqRes != null && originalReqRes.response() != null) {
                                original.setOriginalResponse(originalReqRes.response());
                            }
                        } catch (Exception ex) {
                            api.logging().logToError("[ContextMenuProvider] Error sending original request: " + ex.getMessage());
                        }
                        valueReplacer.ParamFuzzerTest(finalRequestResponse.request(),
                                original.getMessageId(),
                                valueReplacer.extractHostFromRequest(finalRequestResponse.request().url()));
                    } else {
                        api.logging().logToError("[ContextMenuProvider] Failed to create OriginalRequestResponse entry for messageId: " + messageId);
                    }
                } catch (Exception ex) {
                    api.logging().logToError("[ContextMenuProvider] Error running suspicious test: " + ex.getMessage());
                }
            });
        });

        // 添加菜单项到子菜单
        headerIntruderMenu.add(allTests);
        headerIntruderMenu.add(addFilterItem);
        headerIntruderMenu.addSeparator();
        headerIntruderMenu.add(protoTest);
        headerIntruderMenu.add(collectedTest);
        headerIntruderMenu.add(suspiciousTest);

        // 添加子菜单到列表
        menuItems.add(headerIntruderMenu);

        return menuItems;
    }

    // 确保在插件卸载时调用此方法
    public void shutdown() {
        executor.shutdown();
    }
}
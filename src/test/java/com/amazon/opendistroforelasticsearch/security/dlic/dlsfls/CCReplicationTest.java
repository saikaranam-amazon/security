package com.amazon.opendistroforelasticsearch.security.dlic.dlsfls;

import com.amazon.opendistroforelasticsearch.security.OpenDistroSecurityPlugin;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.function.Supplier;
import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.cluster.health.ClusterHealthStatus;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.junit.Assert;
import org.junit.Test;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.ActionRequest;
import org.elasticsearch.action.ActionRequestValidationException;
import org.elasticsearch.action.ActionResponse;
import org.elasticsearch.action.ActionType;
import org.elasticsearch.action.IndicesRequest;
import org.elasticsearch.action.IndicesRequest.Replaceable;
import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.support.ActionFilters;
import org.elasticsearch.action.support.HandledTransportAction;
import org.elasticsearch.action.support.IndicesOptions;
import org.elasticsearch.action.support.WriteRequest.RefreshPolicy;
import org.elasticsearch.action.support.master.AcknowledgedRequest;
import org.elasticsearch.action.support.master.AcknowledgedResponse;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.cluster.metadata.IndexNameExpressionResolver;
import org.elasticsearch.cluster.node.DiscoveryNodes;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.io.stream.NamedWriteableRegistry;
import org.elasticsearch.common.settings.ClusterSettings;
import org.elasticsearch.common.settings.IndexScopedSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.settings.SettingsFilter;
import org.elasticsearch.common.xcontent.NamedXContentRegistry;
import org.elasticsearch.common.xcontent.XContentType;
import org.elasticsearch.env.Environment;
import org.elasticsearch.env.NodeEnvironment;
import org.elasticsearch.node.Node;
import org.elasticsearch.node.PluginAwareNode;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.repositories.RepositoriesService;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestHandler;
import org.elasticsearch.script.ScriptService;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;
import com.amazon.opendistroforelasticsearch.security.test.DynamicSecurityConfig;
import org.elasticsearch.tasks.Task;
import org.elasticsearch.threadpool.ThreadPool;
import org.elasticsearch.transport.Netty4Plugin;
import org.elasticsearch.transport.TransportService;
import org.elasticsearch.watcher.ResourceWatcherService;

public class CCReplicationTest extends AbstractDlsFlsTest {

    public static class MockReplicationPlugin extends Plugin implements ActionPlugin {
        public static String injectedRoles = null;

        public MockReplicationPlugin() {
        }

        @Override
        public Collection<Object> createComponents(Client client, ClusterService clusterService, ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService, ScriptService scriptService,
            NamedXContentRegistry xContentRegistry, Environment environment,
            NodeEnvironment nodeEnvironment, NamedWriteableRegistry namedWriteableRegistry,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<RepositoriesService> repositoriesServiceSupplier) {
            if(injectedRoles != null)
                threadPool.getThreadContext().putTransient(ConfigConstants.OPENDISTRO_SECURITY_INJECTED_ROLES, injectedRoles);
            return new ArrayList<>();
        }

        @Override
        public List<ActionHandler<? extends ActionRequest, ? extends ActionResponse>> getActions() {
            return Arrays.asList(new ActionHandler<>(MockReplicationAction.INSTANCE, TransportMockReplicationAction.class));
        }

        @Override
        public List<RestHandler> getRestHandlers(Settings settings, RestController restController, ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings, SettingsFilter settingsFilter, IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster) {
            return null;
        }
    }

    public static class MockReplicationAction extends ActionType<AcknowledgedResponse> {
        public static final MockReplicationAction INSTANCE = new MockReplicationAction();
        public static final String NAME = "indices:data/read/plugins/replication/file_chunk";
        private MockReplicationAction() {
            super(NAME, AcknowledgedResponse::new);
        }
    }

    public static class MockReplicationRequest extends AcknowledgedRequest<MockReplicationRequest> implements Replaceable {
        private String index;
        public MockReplicationRequest(String index) {
            this.index = index;
        }

        public MockReplicationRequest(StreamInput inp) throws IOException {
            index = inp.readString();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(index);
        }

        @Override
        public ActionRequestValidationException validate() {
            return null;
        }

        @Override
        public IndicesRequest indices(String... strings) {
            return this;
        }

        @Override
        public String[] indices() {
            return new String[]{index};
        }

        @Override
        public IndicesOptions indicesOptions() {
            return IndicesOptions.strictSingleIndexNoExpandForbidClosed();
        }

        @Override
        public boolean includeDataStreams() {
            return false;
        }
    }

    public static class TransportMockReplicationAction extends HandledTransportAction<MockReplicationRequest, AcknowledgedResponse> {

        @Inject
        public TransportMockReplicationAction(TransportService transportService,
            ActionFilters actionFilters) {
            super(MockReplicationAction.NAME, transportService, actionFilters, MockReplicationRequest::new);
        }

        @Override
        protected void doExecute(Task task, MockReplicationRequest request, ActionListener<AcknowledgedResponse> actionListener) {
            actionListener.onResponse(new AcknowledgedResponse(true));
        }
    }

    //Wait for the security plugin to load roles.
    private void waitForInit(Client client) throws Exception {
        try {
            client.admin().cluster().health(new ClusterHealthRequest()).actionGet();
        } catch (ElasticsearchSecurityException ex) {
            if(ex.getMessage().contains("OpenSearch Security not initialized")) {
                Thread.sleep(500);
                waitForInit(client);
            }
        }
    }

    @Override
    void populateData(TransportClient tc) {
        tc.index(new IndexRequest("hr-dls").type("config").id("0").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"User\": \"testuser\",\"Date\":\"2021-01-18T17:27:20Z\",\"Designation\":\"HR\"}", XContentType.JSON)).actionGet();
        tc.index(new IndexRequest("hr-fls").type("config").id("1").setRefreshPolicy(RefreshPolicy.IMMEDIATE)
            .source("{\"User\": \"adminuser\",\"Date\":\"2021-01-18T17:27:20Z\",\"Designation\":\"CEO\"}", XContentType.JSON)).actionGet();
    }

    @Test
    public void testReplicationWithDLS() throws Exception {
        setup(Settings.EMPTY, new DynamicSecurityConfig().setSecurityRoles("roles_ccreplication.yml"), Settings.EMPTY);

        Assert.assertEquals(clusterInfo.numNodes, clusterHelper.nodeClient().admin().cluster().health(
            new ClusterHealthRequest().waitForGreenStatus()).actionGet().getNumberOfNodes());
        Assert.assertEquals(ClusterHealthStatus.GREEN, clusterHelper.nodeClient().admin().cluster().
            health(new ClusterHealthRequest().waitForGreenStatus()).actionGet().getStatus());

        final Settings tcSettings = Settings.builder()
            .put(minimumSecuritySettings(Settings.EMPTY).get(0))
            .put("cluster.name", clusterInfo.clustername)
            .put("node.data", false)
            .put("node.master", false)
            .put("node.ingest", false)
            .put("path.data", "./target/data/" + clusterInfo.clustername + "/cert/data")
            .put("path.logs", "./target/data/" + clusterInfo.clustername + "/cert/logs")
            .put("path.home", "./target")
            .put("node.name", "testclient")
            .put("discovery.initial_state_timeout", "8s")
            .put("opendistro_security.allow_default_init_securityindex", "true")
            .putList("discovery.zen.ping.unicast.hosts", clusterInfo.nodeHost + ":" + clusterInfo.nodePort)
            .build();

        // Set roles for the user
        MockReplicationPlugin.injectedRoles = "ccr_user|opendistro_security_human_resources_trainee";
        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenDistroSecurityPlugin.class).start()) {
            waitForInit(node.client());
            node.client().execute(MockReplicationAction.INSTANCE, new MockReplicationRequest("hr-dls"));
            Assert.assertFalse(true);
        } catch (Exception ex) {
            log.warn(ex.getStackTrace());
            Assert.assertNotNull(ex);
            Assert.assertTrue(ex.getMessage().contains("Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated"));
        }

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenDistroSecurityPlugin.class, MockReplicationPlugin.class).start()) {
            waitForInit(node.client());
            node.client().execute(MockReplicationAction.INSTANCE, new MockReplicationRequest("hr-fls"));
        } catch (ElasticsearchSecurityException ex) {
            log.warn(ex);
            Assert.assertNotNull(ex);
            Assert.assertTrue(ex.getMessage().contains("Cross Cluster Replication is not supported when FLS or DLS or Fieldmasking is activated"));
        }

        try (Node node = new PluginAwareNode(false, tcSettings, Netty4Plugin.class, OpenDistroSecurityPlugin.class, MockReplicationPlugin.class).start()) {
            waitForInit(node.client());
            AcknowledgedResponse res = node.client().execute(MockReplicationAction.INSTANCE, new MockReplicationRequest("hr-normal")).actionGet();
            Assert.assertTrue(res.isAcknowledged());
        }
    }

}

